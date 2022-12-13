// To hash a password, we need 2 steps
// 1. create a salt 
// 2. and need to use this salt along with the password to create a hashed password
// the purpose of the salt is that if we hash a normal password, we run that password through some kind of password using a hash function and that is going to respond and return to us the hashed password. Now if multiple people have the same password, then the hash function is going to return the same hashed password(string) which means if multiple users have same password, they are going to have exact same hash in our database which makes it easy if a potential malicious gets access to our database and they cracked one password then they are able to crack every other password that looks exactly the same and has the same hash. So the way a salt works is we hash our password but what we do is we take some kind of salt and we add it to the beginning of the password before we hash it and this salt is differnt for every single user which means that when we hash our password it will look completely different even though the passwords are exactly the same. This just makes it so that our database is more secure. If someone gets access to it and then they are not able to hash and break people's passwords bcz we have salt. We just need to make sure that we store this salt along with the password so when user tries to login we can use the same salt when we hash the password and luckily "bcrypt" takes care of all this for us.

// "bcrypt" is AN ASYNCHRONOUS LIBRARY SO WE HAVE TO USE ASYNCHRONOUS FUNCTION WITH IT.


const express = require('express');
const app = express();
const bcrypt = require('bcrypt');

app.use(express.json()); // it ensures that we can use json as input and other stuffs
const users = []

app.get('/users',(req,res)=>{
    res.json(users);
})

app.post('/users', async (req,res)=>{
    // const user = {name:req.body.name,password:req.body.password};
    // users.push(user);  // problm here is that our password is stored as plain text and anyone can access it if get the access of DATABASE, so it's not the good way to do this. SO FOR THIS REASON WE NEED THAT password SHOULD BE HASHED SUCH THAT IF SOMEONE GETs ACCESS TO THE DATABASE, THEY THEY ACTUALLY WON'T KNOW WHAT THE USERS PASSWORDS ARE, this is where "bcrypt" comes in
    
    // So now let's make our password secure using "bcrypt"
    try{
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(req.body.password,salt);
        // console.log(salt);
        // console.log(hashedPassword);
        const user = {name:req.body.name,password:hashedPassword}; // hashed password already has info about salt so there is no need to mention salt seperately
        users.push(user);
        res.status(201).send();
    } catch(err){
        res.status(500).send();
    }

    // res.status(201).json();
})

app.post('/users/login',async (req,res)=>{
    const user = users.find(user => user.name = req.body.name) // it will find the user with the given name as request

    // check if user is present or not
    if(user == null){
        return res.status(400).send("Can't find User");
    }

    // Now we will check whether password matches or not, will use await bcz "bcrypt" is an asynchronous library
    try{
        // here we will compare the passwords one user passed in the request and other that has been stored in the database(here in the array) corresponding to the matching user name
        if(await bcrypt.compare(req.body.password,user.password)){ // will return true if both are same or passwords are matching
            res.status(200).send("Successfully Loged in 😇")
        } else{
            res.status(404).send("Incorrect Credentials 😒")
        }
    } catch(err){

    }
})

app.listen(3000,()=>{
    console.log("server is running fine!!");
})