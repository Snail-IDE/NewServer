const Database = require("easy-json-database");
const Log = new Database(`${__dirname}/../log.json`);

const log = (type, message) => {
    const data = {};
    data.type = type;
    data.message = message;

    console.log(data);
    Log.set('logs', [data, ...(Log.get('logs') ?? [])]);
};

module.exports = log;