const webpack = require( 'webpack' );
const path = require( 'path' );
const TerserPlugin = require( 'terser-webpack-plugin' );

const PATHS = {
  src: path.resolve( __dirname, 'src' ),
  dist: path.resolve( __dirname, 'dist' )
};

const { NODE_ENV = 'production' } = process.env;

const defaultConfig = {
  mode: 'production',
  output: {
    path: PATHS.dist,
    filename: 'enface.auth.node.js',
    pathinfo: false,
    globalObject: 'this',
    library: 'EnfaceAuth',
    libraryTarget: 'umd'
  },
  target: 'node',
  module: {
    rules: [
      {
        test: /\.js$/,
        include: PATHS.src,
        use: [
          {
            loader: 'babel-loader',
            options: {
              presets: [
                [
                  '@babel/preset-env',
                  {
                    modules: false,
                    targets: {
                      browsers: [
                        'last 2 versions',
                        'safari >= 7',
                        'ie > 10',
                        'not op_mini all'
                      ]
                    }
                  }
                ]
              ]
            }
          }
        ]
      }
    ]
  },

  plugins: [
    new webpack.DefinePlugin( {
      'process.env': {
        NODE_ENV: JSON.stringify( NODE_ENV )
      }
    } )
  ],

  optimization: {
    removeAvailableModules: false,
    removeEmptyChunks: false,
    minimizer: [
      new TerserPlugin()
    ]
  }
};

module.exports = [ {
  ...defaultConfig
} ];
