'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.bulkUpdate('AppUsers', {
      encryption_key: 'default_encryption_key' 
    }, {
      encryption_key: null
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.bulkUpdate('AppUsers', {
      encryption_key: null
    });
  }
};