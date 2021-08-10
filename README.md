# Enface authorization Node.js library

![](https://lh3.googleusercontent.com/C6975GR-Hv9vpPYVvQFUQ2_ywxhfKHnUulJJjqX_9feNEXFnTNdTWqu_s4-tbeCopVc6caNfq7NlMxpzmiGt8GnM0h3n-LUzwTbAgWmReW8YeDthTOWlwKflMJHSxkg4L6t5TOYB860zwmwOq-r8tPBcWj3pkW56CA3Wijv1aZ9p6BAG8nks3Z16EdCTj-CRj7JRyiya5flD5N-tadQxA9PK1_e7gVlrpW57p0mxyEB8pEQ3sltTZ1MZGMBGVMM7DpuSiV-X7nGqN2MB0mxi8d93Ztnt3dGHvKhy5lRI0McBLS8chPSei0Nwjm0QgbpqiMpesGSGVuG6q_o5tcoe27-YCFl5iQFYGqfzo6oFbszv7GGBmH2vqoTadxPupGEiHX_pbJMbVlRkTl_8Bwak1mEnx4IgHrBhyOOyljwX0wATguhBaAEKCDrbTPH8oUXdQJtwB71uR8dVVFJtF9u6vlSAg_WHEzivQFgp8KPoWpuUUJgY9zuYkvSs97sBeEkIKulIHAsIp0RNjg7y3pPiT5Hw41R7ulGBb5WA3SSRkIzbBbVYduMojNgkUkLtwSJMhGn4YyF6ucnPPofqeCKGmRIoz7h3ZiGqyJGZb_cJXxxJ4Tq9g2sVHxqnuQTUP5fFRbeq2vGG22HoFkjhGgNIVchpRNFmYw=w108-h150-no)

Enface offers biometric authorization feature for any websites (or apps) using [Enface application](https://apps.apple.com/us/app/enface/id1464761858 "Enface application") and neural networks face recognition engine. Our authentication process is based on strong cryptographic algorithms combined with biometric user's data.

To enable our solution you should pass the following steps:

- Register for free at [Enface website](https://admin.enface.io "Enface website"), visit “[Biometric authorization](https://admin.enface.io/authorization "Biometric authorization")”page  and click on the “Add new project” button. **Setup “API key for authentication”** from the drop-down of the project panel. **Copy the “Project id” and “Secret key” variables for future usage.**
- Integrate the [frontend widget](https://github.com/safead/enface-auth-widget "frontend widget") on your website or application.
- Setup backend environment, using instructions below.

This package is for backend integration with Node.js environment. There are 2 different modes of backend library operation – using WebSockets or Express web server. WebSockets are recommended way of backend operation, but requires an additional port to be opened for connections. Instead of WebSockets, you can provide any existing Express instance to enable HTTP/S mode.

## Installation

### npm

```bash
npm i --save enface-auth-node
```

### yarn

```bash
yarn add enface-auth-node
```

## Usage

ES2015 module import:
```js
import { EnfaceAuth } from "enface-auth-node";
```
CommonJS module require:
```js
const { EnfaceAuth } = require("enface-auth-node");
```

### Initialization:
```js
new EnfaceAuth({

  port: <number> || httpServer: <object>,
  callbackUrl: <string>,
  projectId: <string>,
  secretCode: <string>,
  debug: <boolean>, // debug logs

  onCheckCurrentStatus(userId) {
    // is biometric sign in for current user enabled or not?
  },

  onUserValidate(userData) {
    // validate logged in user by token, session id, cookie etc.
  },

  onActivate(userId, bioId, userPublicKey) {
    // linking user with his biometric id
  },

  onUserPublicKey(userId) {
    // get user application public key
  },

  onUserTokenByBioId(bioId) {
    // create athorization data and send it to the frontend
  },

});
 ```
### Backend preparations:

To activate biometric authorization on any resource **with its current user base** it is required to create a permanent storage with biometric id and user id linking. There should be at least 3 kind of data fields in each stored record:
- **internal user id** (any searchable type to identify your user)
- **biometric id** provided by Enface service upon activation (UUID)
- application **RSA public key** (TEXT, up to 1kb)

### EnfaceAuth parameters and callbacks (all functions can be asynchronous):

`port (integer)`

If this variable is set, EnfaceAuth module is going to start in WebSockets mode and will try to open specified port to listen all incoming connections. In this mode both [frontend widget](https://github.com/safead/enface-auth-widget "frontend widget") and Enface API server should be able to connect to ws(s)://yourdomain.com:port to process required operation and checks.

`httpServer (Express instance)`

If this variable is set, EnfaceAuth module will start in HTTP/S mode and will use default Express port to listen all the connections. In this mode both [frontend widget](https://github.com/safead/enface-auth-widget "frontend widget") and Enface API server should connect to http(s)://yourdomain.com to process required operation and checks.

**Important: only one of the variables (port or httpServer) should be set, otherwise there will be an exception thrown by the EnfaceAuth library.**

`callbackUrl: <string>`

ws(s) or http(s) URL to connect to this backend module, constructed regarding “port” or “httpServer” variables above.

`projectId: <string>`

“Project id” variable from the [Enface website](https://admin.enface.io "Enface website") project description.

`secretCode: <string>`

“Secret key” variable from the [Enface website](https://admin.enface.io "Enface website") project description.

`onCheckCurrentStatus(userId): <boolean>`

This callback used to determine the state of current user biometric authorization state (turned ON or OFF). Here the link of “userId” with his “bioId” should be checked and returned (see example below).

`onUserValidate(userData) : <any>`

This function is used to determine “userId” by secured identification data, sent from the frontend (token, session id, cookie etc.).

`onActivate(userId, bioId, userPublicKey) : <boolean>`

This function will be called after Enface API server processes the enable/disable user request, providing “userId” (determined in “onUserValidate”), “bioId” (calculated by Enface using user biometric data) and “userPublicKey” from the Enface application in PEM encoding (string up to 1kb).

-	If the backend table contains any records with this “userId", they should be deleted and "false”returned (Biometric sign in is turned OFF);
-	If the backend storage do not contains any record with this “userId” - a new record, containing “userId”, “bioId” and “userPublicKey” should be created. The result of the callback must be “true” in this case (Biometric sign in is turned ON).

`onUserPublicKey(userId) : <string>`

To achieve maximum security level, the [Enface application](https://apps.apple.com/us/app/enface/id1464761858 "Enface application") instance will be checked using asynchronous cryptography. “userPublicKey”, stored at “onActivate” stage should be received here, to accomplish these checks. Perform the search using provided “userId” and return the value, if any.

`onUserTokenByBioId(bioId) : <any>`

This function will be called after Enface API server successfully processed the authorization request, providing “bioId” to find the linked “userId”. At this moment an authorization data (token, session id, cookies etc.) should be generated according your backend security logic. All necessary security checks are already done at this moment and [Enface Widget](https://github.com/safead/enface-auth-widget "Enface Widget") at the frontend is going to receive generated token.

### Here is how EnfaceAuth is integrated at our own Node.js server.

```js
new EnfaceAuth({

  httpServer: app, // app is the existing Express instance
  projectId: process.env.AUTH_PRODUCT_ID,
  secretCode: process.env.BIO_AUTH_SECRET,
  callbackUrl: 'https://enface-api-server.herokuapp.com',
  // full callback URL (we use HTTPS mode as we provide “httpServer” variable above)

  async onCheckCurrentStatus(userId) {
    // record with “userId” exists - biometric signin is enabled
    const bioUser = await models.AuthBioLink.findByUserId(userId);
    return !!bioUser;
  },

  onUserValidate(userData) {
    // frontend widget will send this JWT token to identify user
    const token = jwt.verify(userData, process.env.JWT_SECRET);
    return token.id;
  },

  async onActivate(userId, bioId, userPublicKey) {
    // check “userId” record existance
    const bioUser = await models.AuthBioLink.findByUserId(userId);
    if (bioUser) {
      // delete record and return “false”. Biometric is now turned OFF
      await bioUser.destroy({ userId });
      return false;
    }

    // add new record and return “true”. Biometric is now turned ON
    await models.AuthBioLink.create({
      userId,
      bioId,
      userPublicKey,
    });
    return true;
  },

  async onUserPublicKey(userId) {
    // get user public key if record with “userId” exists
    const bioUser = await models.AuthBioLink.findByUserId(userId);
    return bioUser ? bioUser.userPublicKey : null;
  },

  async onUserTokenByBioId(bioId) {
    // look for a record with “bioId"
    const bioUser = await models.AuthBioLink.findByBioId(bioId);
    if (!bioUser) return false; // no records found

    // look for the user record in main users table (we know “userId”)
    const user = await models.User.findById(bioUser.userId);
    if (!user || !user.isActive) return false;

    /*
    * use your backend custom authorization logic
    * the main goal at this moment is to generate secutity token
    * which will be sent to Enface Widget automatically
    * and let the user continue authorized
    */

    // here is how we do it: generate and return JWT token
    return utils.createToken(user, process.env.SECRET, constants.SESSION_JWK_TIMEOUT);
  }

});
```
