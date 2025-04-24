'use strict';
const { Model } = require('sequelize');
const bcrypt = require('bcrypt');

module.exports = (sequelize, DataTypes) => {
  class AppUser extends Model {
    static associate(models) {
    }
  }

  AppUser.init(
    {
      firstName: DataTypes.STRING,
      lastName: DataTypes.STRING,
      email: {
        type: DataTypes.STRING,
        unique: true
      },
      password: DataTypes.STRING,
      encryption_key: {
        type: DataTypes.STRING,
        allowNull: true
      }
    },
    {
      sequelize,
      modelName: 'AppUser',
    }
  );

  AppUser.prototype.comparePassword = async function (plainTextPassword) {
    console.log('Plain-text password:', plainTextPassword);
    console.log('Hashed password from DB:', this.password);
    const isMatch = await bcrypt.compare(plainTextPassword, this.password);
    console.log('Password match result:', isMatch);
    return isMatch;
  };
  
  return AppUser;
};

