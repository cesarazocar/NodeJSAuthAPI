/*
RESTFul Services by NodeJs
Autor: César Azócar
fecha: 07/04/2019
*/

var crypto = require('crypto'); //to encrypt passport
var uuid = require('uuid'); // to create unique id string
var express = require('express'); //to easy creaty RestFul API endpoint
var mysql = require('mysql');// To connect with MySQL
var bodyParser = require('body-parser');//to parse parameter from API request

//Connect to MySQL
var con = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'demonodejs'

});

//password ULTIL
var genRandomString = function (length) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
};

var sha512 = function (password, salt) {
    var hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt: salt,
        passwordHash: value
    };
};

function saltHashPassword(userPassword) {
    var salt = genRandomString(16);
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}

function checkHashPassword(userPassword, salt) {
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}

var app = express();
app.use(bodyParser.json());//Accept JSON params
app.use(bodyParser.urlencoded({ extended: true })); //Accept URL Encoded params

app.post('/register/', (req, res, next) => {

    var post_data = req.body;  //Get POST params
    var uid = uuid.v4(); //Get UUID v4 like '110abacsasas-af0x-90333-casasjkajksk
    var plaint_password = post_data.password; // Get password from post params
    var hash_data = saltHashPassword(plaint_password);
    var password = hash_data.passwordHash; // Get hash value 
    var salt = hash_data.salt; //Get salt
    var name = post_data.name;
    var email = post_data.email;

    con.query('Select * FROM user where email =?', [email], function (err, result, fields) {
        con.on('error', function (err) {
            console.log('[MySQL ERROR]', err);
        });

        if (result && result.length)
            res.json('User already exist!!!');
        else {
            con.query('INSERT INTO `user`(`unique_id`, `name`, `email`, `encrypted_password`, `salt`, `created_alt`, `updated_alt`) VALUES (?,?,?,?,?,NOW(),NOW())', [uid, name, email, password, salt], function (err, result, fields) {
                con.on('error', function (err) {
                    console.log('[MySQL ERROR]', err);
                    res.json('Register error', err);
                });
                res.json('Register successfull');
            })
        }

    });

})

app.post('/login/', (req, res, next) => {

    var post_data = req.body;
    //Extract email and password from request
    var user_password = post_data.password;
    var email = post_data.email;


    con.query('Select * FROM user where email =?', [email], function (err, result, fields) {
        
        con.on('error', function (err) {
            console.log('[MySQL ERROR]', err);
        });

        if (result && result.length) {
            var salt = result[0].salt; //Get salt of result if account exists
            var encrypted_password = result[0].encrypted_password;
            //Hash password from login request with salt in database
            var hashed_password = checkHashPassword(user_password, salt).passwordHash;
            if (encrypted_password == hashed_password) {
                res.end(JSON.stringify(result[0]));
                console.log('user login sucessfully ' + email);
            }
            else {
                res.end(JSON.stringify('Wrong password'));
                console.log('wrong password');
            }
        }
        else {
            res.json('User not exists!!!');
            console.log('user not exists ' + email);
        }
    });
    /*
        con.query('select * from user where email =?', [email],function(error,result,fields){
            con.on('error',function(err){
                console.log('MYSQL ERROR',err);
                res.json('Register error:',err);    
                });
                
    
        })*/
})


/*app.get("/",(req,res,next)=>{
    console.log('Password: 123456');
    var encrypt = saltHashPassword("123456");
    console.log('Encrypt: '+encrypt.passwordHash);
    console.log('Salt:'+encrypt.salt);

});
*/
//Start Server
app.listen(3000, () => {
    console.log('Cesar RestFull running on port 3000');
})

