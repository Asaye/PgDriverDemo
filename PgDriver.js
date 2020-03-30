const net = require('net');          // a module to create a socket
const crypto = require('crypto');      // a module to hash password
const TYPES = require('./types.json'); // a local file for column 
                                       // data type resolution
module.exports = class PgDriver {
  
   constructor() {
      this.socket = null;   // the socket instance
      this.config = null;   // client's configuration data
      this.callback = null; // callback function sent by the client
      this.data = null;     // data received from the database
      this.queryQueue = []; // queue of queries received from the
                            // client      
      this.results = {      // result to be sent to the client
         fields: [], 
         types: [], 
         rows: [],
         status: ""
      };
      this.isReadyForQuery = false;  // a flag which signals whether   
                                     // the database is ready to   
                                     // process the next query
   }

   connect(config, callback) { 
      this.config = config;
      this.queryQueue.push({ "callback": callback });
      this.socket = new net.Socket();
      this._addListeners();
      this.socket.connect(config.port, config.host); 
   }
  
  _addListeners() {
     // event listener fired when the socket is connected
     this.socket.on("connect", (err) => { 
        // remove the first element in the queryQueue and assign it to 
        // 'next' variable
        const next = this.queryQueue.shift(); 
        if (err) {
           next.callback(err);
           return;
        }
        next.callback(null, "Connection successful.");
        this._startup();     // proceed to the startup configuration
     });
     // event listener fired when data is received from the server
     this.socket.on("data", (data) => { this._parser(data); });
     // event listener fired when connection error occurs
     this.socket.on("error", (err) => {
        console.log("Connection terminated");
     });

     // custom event listener fired when the server is ready to 
     // process the next query
     this.socket.on("readyForQuery", () => { 
        if (this.queryQueue.length > 0) {
           // set the flag to false so that another query won't 
           // interrupt this one
           this.isReadyForQuery = false;
           const next = this.queryQueue.shift(); 
           this.socket.write(next.buffer);
           this.callback = next.callback;
        } else {
           this.isReadyForQuery = true;
        }
     });
   }
  
   _startup() { 
     const user = this.config.user;
     const db = this.config.database;
     const params = `user\0${user}\0database\0${db}\0\0`;
     // allocate the required bytes of memory
     const buffer = Buffer.alloc(4 + 4 + params.length);
     // write 4 bytes of the message length (start : 0, default)
     buffer.writeInt32BE(buffer.length); 
     // write 4 bytes the protocol version number (start: 4 (0 + 4)) 
     buffer.writeInt32BE(196608, 4);
     // write the key-value pairs (start: 8 (0 + 4 + 4))
     buffer.write(params, 8); 

     // send the buffer to the database server      
     this.socket.write(buffer); 
  }

  _parser(data) {
     this.data = data;
     var type, length, offset = 0;
     do {
        // read 1byte message type and increment the index
        type = String.fromCharCode(data[offset++]); 
        // read 4bytes of integer (length) starting from 'offset'
        length = data.readInt32BE(offset);
        // increment the offset to skip the 4bytes just read      
        offset += 4;

        // delegate the responsible function which handles the message     
        switch (type) {
           case 'R': {
              this._password(offset);break;
           }
           case 'E': {
              this._error(offset, length);break;
           }
           case 'Z': { 
              this.socket.emit('readyForQuery');break;
           }         
           case 'T': {
              this._fields(offset);break;
           }
           case 'D': {
              this._rows(offset);break;
           }
           case 'C': {
              const i = data.indexOf(0, offset);
              this.results.status = data.toString('utf-8', offset, i);
              this.callback(null, this.results);break;
           }
        } 
        // adjust the offset by increasing the length of the actual
        // message = (length - 4), b/c 'length' includes the 4bytes
        // storing the length itself.
        offset += (length - 4); 
     } while (offset < data.length); 
  }

  _password(offset) { 
     var start = offset; 
     // read 4bytes of password type.For password hashing, the default
     // value is 5 which indicates that MD5 password encryption is 
     // required. For other hashing types, refer the documentation
     const passwordType = this.data.readInt32BE(start); 
     start += 4;
     if (passwordType === 0) {         // Authentication ok!
        return;
     } else if (passwordType === 5) {  // MD5 hashing required
        // read 4bytes of salt which will be used for hashing
        const salt = this.data.slice(start, start + 4);
        // MD5 hashing
        const str = this.config.password + this.config.user;
        var md5 = crypto.createHash('md5');
        const inner = md5.update(str,  'utf-8').digest('hex');
        const buff = Buffer.concat([Buffer.from(inner), salt]);
        md5 = crypto.createHash('md5');
        const pwd = 'md5' + md5.update(buff, 'utf-8').digest('hex');
        // Send the hashed password to the database
        // length = 4 (the 4bytes for length) + the password length +
        // 1 (the null terminator for the password (string))
        const length = 4 + pwd.length + 1; 
        const buffer = Buffer.alloc(1 + length); // 1 for message type 
        buffer.write('p');  // p: message type character for password   
        buffer.writeInt32BE(length, 1); // start : 1 (0 + 1)
        buffer.write(pwd + '\0', 5); // start : 5 (0 + 1 + 4)

        this.socket.write(buffer); 
     }
  }

  query(text, callback) {
     // length = 4bytes (length) + text length + 1byte (null 
     // terminator for the text)
     const length = 4 + text.length + 1;
     const buffer = Buffer.alloc(1 + length); //1byte for message type

     buffer.write('Q'); // Q : message code for simple query
     buffer.writeInt32BE(length, 1); // start : 1 (0 + 1)
     // write the null terminated SQL string 
     buffer.write(text + '\0', 5);   // start : 5 (0 + 1 + 4)

     // if the database server is ready for query and the queue is
     // empty, send the query directly. Otherwise, add the buffer and
     // callback to the queryQueue
     if (this.isReadyForQuery && this.queryQueue.length === 0) {
        // set the 'isReadyForQuery' flag to false so that another 
        // query won't interrupt this one
        this.isReadyForQuery = false; 
        this.callback = callback;
        this.socket.write(buffer); 
     } else {
        this.queryQueue.push({
           "buffer": buffer, 
           "callback": callback 
        });
     }
  }

  _error(offset, length) {
     var start = offset, err = {}, fieldType, field, type, end;

     const errorFields = {
        "C": "code", 
        "M": "message", 
        "S": "severity"
     };
     // loop until all zero terminators are traversed
     while (start < length) {
        fieldType = String.fromCharCode(this.data[start]);
        start++; // move to the next byte after the field type
        if (fieldType == "0") { 
           continue; // no string follows as per the protocol
        } 
        // find the next index of a null-terminator after 'start' 
        end = this.data.indexOf(0, start); 
        field = this.data.toString("utf-8", start, end);
        // check if 'fieldType' is 'C', 'S' or 'M'
        type = errorFields[fieldType]; 
        if (type) { 
           err[type] = field;
        }
        // move to the next byte after the zero terminator to parse
        // the next field type
        start = end + 1; 
     }
     if (err.severity === "ERROR" || err.severity === "FATAL") {
        this.callback(err); // notify the client about the error
     } 
  }
  
  _fields(offset) {
     var start = offset, fieldName, end, oid_type; 
     // read 2bytes of integer (the number of fields)
     const nFields = this.data.readInt16BE(start); 
     start += 2; // skip the two bytes just read
     if (nFields === 0) return; // no fields
     for (let i = 0; i < nFields; i++) {
        // find the index of a null-terminator starting from the 
        // start of string to get the field name
        end = this.data.indexOf(0, start); 
        fieldName = this.data.toString("utf-8", start, end); 
        this.results.fields.push(fieldName);

        // move to the byte next after the null-terminator
        start = end + 1;
        // skip 4 bytes (object id of table) + 2 bytes (attribute 
        // number of the column)
        start += (4 + 2); 
        // read 4 bytes integer - the object id of the data type
        oid_type = this.data.readInt32BE(start); 
        // resolve the OID to actual data type using the global TYPES 
        // variable add it to the results variable      
        this.results.types.push(TYPES[oid_type]); 
        // skip 4bytes (oid_type) + 2bytes (data type size) + 4bytes 
        // (type modifier) + 2bytes (format code) to start at the 
        // right point for the next field
        start += (4 + 2 + 4 + 2); 
     }
  }
  
  _rows(offset) {
     var start = offset, row = {}, len, val_col, name_col;
     const nColumns = this.data.readInt16BE(start); 
     start += 2; 

     if (nColumns === 0) return;   // no columns
     for (let i = 0; i < nColumns; i++) {
        // get the column name from the 'results' variable  
        name_col = this.results.fields[i]; 
        // read 4bytes of the number of bytes of column data   
        len = this.data.readInt32BE(start); 
        start += 4; 
        if (len === -1) {      // column value is null
           row[name_col] = null;
        } else {
           // for simplicity, we will convert all column data to 
           // string. In real case though, the column data should be 
           // casted into the correct data type based on the data type
           // of the column obtained in the field description message
           val_col = this.data.toString('utf-8', start, start + len);
           row[name_col] = val_col;
           start += len;     // skip len bytes of val_col
        } 
     }
     // add the current row to the rows property of results     
     this.results.rows.push(row); 
  }
  
  close() {
     // allocated memory for 1byte ('X') + 4 bytes (length)
     const buffer = Buffer.alloc(1 + 4); 
     buffer.write('X'); 
     buffer.writeInt32BE(4, 1); // start : 1
     // a double action - send terminate message and then close the 
     // socket
     this.socket.end(buffer); 
  }
}
