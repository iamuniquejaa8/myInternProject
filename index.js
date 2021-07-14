const bodyParser = require("body-parser");
const express=require("express")
const app=express();
const path=require("path");
const bodyparser=require("body-parser");
const port=process.env.PORT || 3000;
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');

const user=require('./model/user');
const JWT_SECRET='wefvbFNlbkjbnlfmDVNdvjfdnfdgkdsnkgnsdbg'

const mongoose=require('mongoose');
mongoose.connect("mongodb://localhost:27017/login-app-db",{
    useNewUrlParser:true,
    useUnifiedTopology:true,
    useCreateIndex:true,
    useFindAndModify:false
}).then(()=>{
    console.log("connected");
}).catch((err)=>{
    console.log(`error is ${err}`);
})


app.use("/",express.static(path.join(__dirname,'static')));

app.use(bodyparser.json())

app.post('/api/change-password',async(req,res)=>{
    const {token,newpassword:plainTextPassword}=req.body
    
    
   if(!plainTextPassword || typeof plainTextPassword  !== 'string'){
    return res.json({status : 'error',error:"invalid password"})
}

if(plainTextPassword.length < 4){
   return  res.json({
        status:'error',
        error:"password too small. should be atleast 6 charcters"
    })
}

    
    try{
   const user=jwt.verify(token,JWT_SECRET)
   const _id= User.id

const password=await bcrypt.hash(plainTextPassword)

   await user.updateOne({_id},{
       $set:{
        password
       }

   })

   res.json({status:'ok'})
    }catch(error){
        res.json({status:'error',error:''})
    }
})

app.post('/api/login',async(req,res)=>{

    const {username,password}=req.body;

    const User=await user.findOne({username}).lean()

    if(!User)
    {
        return res.json({status:'error',error:"invalid username/password"})
    }

    if(await bcrypt.compare(password,User.password))
    {
        //the username ,password combination is sucess full

        const token=jwt.sign({
            id:User._id,
            username:User.username
        },JWT_SECRET)


        return res.json({status:'ok',data:token})
    }

    res.json({status:'error',error:'Invalid username/password'})
})




app.post('/api/register',async (req,res)=>{
     
   const {username,password:plainTextPassword}=req.body;


   if(!username || typeof username  !== 'string'){
       return res.json({status : 'error',error:"invalid username"})
   }

   if(!plainTextPassword || typeof plainTextPassword  !== 'string'){
    return res.json({status : 'error',error:"invalid password"})
}

if(plainTextPassword.length < 4){
   return  res.json({
        status:'error',
        error:"password too small. should be atleast 6 charcters"
    })
}


   const password=await bcrypt.hash(plainTextPassword,10)

   try {
       const response=await user.create({
           username,
           password
       })
       console.log(`user created sucessfully: `,response)
   }catch(error)
   {
         if(error.code === 11000)
         return res.json({status:'error',error:'Username already in use'})
     }
     
     res.json({status:'OK'})
})

app.listen(port,()=>{
    console.log(`server is listening on port ${port}`);
})