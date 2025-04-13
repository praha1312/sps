'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn('AppUsers', 'encryption_key', {
      type: Sequelize.STRING,
      allowNull: true 
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.removeColumn('AppUsers', 'encryption_key');
  }
};