const { AppUser } = require('./models');

async function clearTable() {
  try {
    const deletedCount = await AppUser.destroy({
      where: {}, 
      truncate: false
    });

    console.log(`Deleted ${deletedCount} rows from the AppUsers table.`);
  } catch (error) {
    console.error('Error clearing the table:', error);
  }
}

clearTable();