'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class UserPassword extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
    }
  }
  UserPassword.init({
    ownerUserId: DataTypes.INTEGER,
    url: DataTypes.STRING,
    username: DataTypes.STRING,
    password: DataTypes.STRING,
    sharedByUserId: DataTypes.INTEGER
  }, {
    sequelize,
    modelName: 'UserPassword',
  });
  return UserPassword;
};