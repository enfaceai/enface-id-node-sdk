import { v1 as uuid, validate } from 'uuid';
import WebSocket from 'ws';
import https from 'https';
import {
  COMMAND_CHECK,
  COMMAND_READY,
  COMMAND_ERROR,
  COMMAND_ACTIVATED,
  COMMAND_HELLO,
  COMMAND_CHALLENGE,
  COMMAND_AUTH_INIT,
  COMMAND_AUTH_RESULT,
  COMMAND_AUTH,
  COMMAND_AUTH_DECLINED,
  COMMAND_CONNECTION_FAILED,
  COMMAND_CURRENT_USER_TOKEN,
  SOCKET_PING_TIMEOUT,
  AUTHORIZATION_TIME_FRAME,
} from './constants';
import { encrypt, checkIsTrue } from './utils';
import { createChallenge, checkChallenge } from './blockchain';

export class EnfaceAuth {
  constructor({
    debug,
    port = 31313, // optional, default to 31313
    projectId,
    secretCode,
    fields = '', // optional, only user alias will be provided on empty value
    ssl, // ssl credentials { key: 'ascii', cert: 'ascii' }
    onUserValidate,
    onActivate,
    onSuccess,
  }) {
    this.log = debug
      ? console.log.bind(console)
      : () => {};
    this.logError = debug
      ? console.error.bind(console)
      : () => {};
    if (!validate(projectId)) {
      console.error('[EnfaceAuth].constructor.error: bad projectId (should be uuid string)');
      return;
    }
    this.projectId = projectId;
    try {
      this.secretCode = Buffer.from(secretCode, 'base64');
    } catch (error) {
      console.error('[EnfaceAuth].constructor.error: bad secret code');
      return;
    }
    this.fields = fields;
    this.onUserValidate = onUserValidate;
    this.currentUserToken = '';
    this.onActivate = onActivate;
    this.onSuccess = onSuccess;
    this.sessions = {};
    const server = ssl
      ? https.createServer(ssl)
      : null;
    this.log(`[EnfaceAuth] starting ws${server ? 's' : ''} server at port: ${port}`);
    const wsServer = new WebSocket.Server({ server });
    server.listen(port);
    wsServer.on('connection', socket => {
      this.newClient({ client: socket });
      socket.on('message', data => {
        this.request({ client: socket, data });
      });
      socket.on('close', code => {
        this.log(`[EnfaceAuth].socket.on.close ${socket.clientId} closed with code: ${code}`);
        socket.isAlive = false;
        this.sessions[socket.clientId]
        && this.responseFailed({ client: socket, data: { _: COMMAND_CONNECTION_FAILED } });
        delete this.sessions[socket.clientId];
        this.log(`[EnfaceAuth].socket.on.close active sessions ${Object.keys(this.sessions).length}`);
      });
      socket.isAlive = true;
      socket.on('pong', () => { socket.isAlive = true; });
    });
    this.interval = setInterval(() => {
      wsServer.clients.forEach(socket => {
        if (socket.isAlive === false) return socket.terminate();
        socket.isAlive = false;
        return socket.ping(() => {});
      });
    }, SOCKET_PING_TIMEOUT);
    wsServer.on('close', () => {
      clearInterval(this.interval);
    });
  }

  encode(data) {
    return JSON.stringify(data);
  }

  decode(data) {
    return JSON.parse(data);
  }

  async request({ client, data }) {
    this.log(`[EnfaceAuth].request, ${data}`);
    try {
      const response = await this.readMessage({ client, data });
      response && this.send({ client, data: response });
    } catch (error) {
      this.logError(`[EnfaceAuth].request error', ${error.message}`);
      this.errorResponse({ client, error: `${error}` });
      this.finalizeSession(client);
    }
  }

  send({ client, data }) {
    this.log('[EnfaceAuth].send', { data });
    client.send(this.encode(data));
  }

  async readMessage({ client, data }) {
    try {
      this.log(`[EnfaceAuth].readMessage, ${this.encode(data)}, clientId, ${client.clientId}`);
      try {
        data = this.decode(data);
      } catch (error) {
        this.logError(`[EnfaceAuth].readMessage, ${error.message}`);
        return this.errorResponse({ client, error: `wrong data received ${data}` });
      }
      switch (data._) {
        case COMMAND_HELLO:
          return this.responseHello({ client, data });
        case COMMAND_CHECK:
          return this.responseActivate({ client, sessionId: data.session_id, alias: data.alias });
        case COMMAND_AUTH_INIT:
          return this.responseInit({ client, data });
        case COMMAND_AUTH_DECLINED:
          return this.responseFailed({ client, data });
        case COMMAND_AUTH:
          return this.responseAuth({ client, data });
        case COMMAND_CURRENT_USER_TOKEN:
          this.currentUserToken = data.payload;
          return false;
        default:
          return this.errorResponse({ client, error: `unknown command ${ data._ }` });
      }
    } catch (error) {
      this.logError(`[EnfaceAuth].readMessage ERROR ${error.message}`);
      return this.errorResponse({ client, error: error.message });
    }
  }

  newClient({ client }) {
    const clientId = uuid();
    this.log(`[EnfaceAuth].newClient ${clientId}`);
    this.sessions[clientId] = {
      client,
      sessionId: uuid(),
      alias: null,
      userId: null,
      clientSessionId: null,
      resolver: null,
    };
    client.clientId = clientId;
    setTimeout(() => {
      this.sessions[clientId] && this.finalizeSession({ clientId });
    }, AUTHORIZATION_TIME_FRAME);
  }

  responseFailed({ client, data }) {
    this.log(`[EnfaceAuth].responseFailed, ${this.encode(data)}, sessionId: ${this.sessions[client.clientId].sessionId}`);
    if (!client.browserSession) return this.errorResponse({ client, error: 'client not found' });
    this.log(`[EnfaceAuth].responseFailed, found clientSessionId ${data.session_id}`);
    this.finalResponse({
      client: client.browserSession.client,
      data: { _: data._ },
    });
    this.finalResponse({ client, data: { _: data._ } });
  }

  responseInit({ client, data }) {
    this.log(`[EnfaceAuth].responseInit, ${this.encode(data)}, sessionId: ${this.sessions[client.clientId].sessionId}`);
    const token = encrypt( // todo Object => ArrayBuffer => Object (after decryption)
      this.sessions[client.clientId].sessionId,
      this.secretCode
    );
    return this.resolve({
      client,
      data: {
        _: data._,
        payload: { id: this.projectId, token },
      },
    });
  }

  async responseHello({ client, data }) {
    this.log(`[EnfaceAuth].responseHello sessionId: ${this.sessions[client.clientId].sessionId}`);
    const session = this.findSession('clientSessionId', data.session_id);
    if (!session) return this.errorResponse({ client, error: 'client not found' });
    client.browserSession = session;
    let secret,
      challenge,
      publicKeySign;
    if (!client.challenge) {
      ({ secret, challenge, publicKeySign } = await createChallenge(data.alias));
      client.secret = secret;
      client.publicKeySign = publicKeySign;
      client.alias = data.alias;
    }
    let payload;
    if (publicKeySign) {
      payload = {
        _: COMMAND_CHALLENGE,
        message: 'continue',
        payload: {
          challenge,
          fields: this.fields,
        },
      };
    } else {
      payload = {
        _: 'error',
        message: 'user not found',
      };
    }
    return this.resolve({ client, data: payload });
  }

  responseActivate({ client, sessionId, alias }) {
    this.log(`[EnfaceAuth].responseActivate, sessionId, ${sessionId}, alias: "${alias}"`);
    const session = this.findSession('sessionId', sessionId);
    if (!session) return this.errorResponse({ client, error: 'client not found' });
    if (session.alias) return this.errorResponse({ client, error: 'session is already activated' });
    session.alias = alias;
    session.clientSessionId = uuid();
    this.finalResponse({
      client,
      data: {
        _: COMMAND_READY,
        client_session_id: session.clientSessionId,
      },
    });
    // send callback to browser's widget
    this.send({
      client: session.client,
      data: { _: COMMAND_ACTIVATED },
    });
  }

  async responseAuth({ client, data }) {
    this.log('[EnfaceAuth].responseAuth', { data });
    if (!client.browserSession) return this.errorResponse({ client, error: 'client not found' });
    if (client.browserSession.alias !== data.alias) {
      return [client.browserSession.client, client].forEach(item => {
        return this.errorResponse({ client: item, error: 'user alias do not match' });
      });
    }
    const challengeResult = await checkChallenge({
      secret: client.secret,
      publicKeySign: client.publicKeySign,
      challengeSigned: data.challenge_signed,
    });
    this.log(`[EnfaceAuth].responseAuth challengeResult: ${challengeResult}`);
    checkIsTrue(challengeResult, 'access denied');
    const result = await this.onSuccess({
      ...data.fields,
      alias: data.alias,
      currentUserToken: this.currentUserToken,
    });
    this.log('[EnfaceAuth].responseAuth onSuccess', { result });
    this.finalResponse({
      client,
      data: {
        _: result.error ? 'error' : data._,
        message: result.error || 'welcome',
      },
    });
    this.finalResponse({
      client: client.browserSession.client,
      data: {
        _: result.error ? 'error' : COMMAND_AUTH_RESULT,
        message: result.error || 'welcome',
        payload: {
          token: result.token,
          linked_id: result.linkedId || '',
        },
      },
    });
    return false;
  }

  async linkSessionToUser({ client, userData }) {
    this.log('[linkSessionToUser]', this);
    try {
      const userId = await this.onUserValidate(userData);
      this.log(`[linkSessionToUser] userId, ${userId}`);
      this.sessions[client.clientId].userId = userId;
      return true;
    } catch (error) {
      return false;
    }
  }

  errorResponse({ client, error }) {
    this.logError(`[EnfaceAuth].errorResponse, ${error}`);
    this.finalResponse({
      client,
      data: { _: COMMAND_ERROR, message: error },
    });
    return false;
  }

  finalResponse({ client, data }) {
    this.log(`[EnfaceAuth].finalResponse to ${client.clientId}`);
    this.resolve({
      client,
      data,
      closeConnection: true,
    });
  }

  resolve({ client, data, closeConnection }) {
    this.log(`[EnfaceAuth].resolve clientId [${client.clientId}], data: ${this.encode(data)}`);
    const session = this.sessions[client.clientId];
    if (!session) return;
    this.send({ client: session.client, data });
    closeConnection && this.closeClient({ client: session.client });
  }

  finalizeSession({ clientId }) {
    this.log(`[EnfaceAuth].finalizeSession clientId ${clientId}`);
    this.sessions[clientId]
    && this.closeClient({ client: this.sessions[clientId].client });
  }

  closeClient({ client }) {
    this.log(`[EnfaceAuth].closeClient ${client.clientId}`);
    delete this.sessions[client.clientId];
    client && client.terminate();
  }

  findSession(paramName, searchValue) {
    for (const key of Object.keys(this.sessions)) {
      if (this.sessions[key][paramName] === searchValue) {
        return this.sessions[key];
      }
    }
    return null;
  }
}

EnfaceAuth.COMMAND_AUTH = COMMAND_AUTH;
EnfaceAuth.COMMAND_CHECK = COMMAND_CHECK;
EnfaceAuth.COMMAND_READY = COMMAND_READY;
