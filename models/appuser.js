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
      hooks: {
        // Before creating a new user, hash the password
        beforeCreate: async (user) => {
          if (user.password) {
            const saltRounds = 10;
            user.password = await bcrypt.hash(user.password, saltRounds);
          }
        },

        // Before updating a user, hash the password if it has changed
        beforeUpdate: async (user) => {
          if (user.changed('password')) {
            const saltRounds = 10;
            user.password = await bcrypt.hash(user.password, saltRounds);
          }
        }
      }
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

