require('dotenv').config(); 

module.exports = {
  development: {
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: process.env.DB_DIALECT,
    dialectOptions: {
      ssl: {
        require: process.env.DB_SSL_REQUIRE === 'true',
        rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED === 'false'
      } 
    }
  },
  test: {
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: `${process.env.DB_NAME}_test`, 
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: process.env.DB_DIALECT
  },
  production: {
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: process.env.DB_DIALECT,
    dialectOptions: {
      ssl: {
        require: process.env.DB_SSL_REQUIRE === 'true',
        rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED === 'false'
      }
    }
  }
};