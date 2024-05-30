import userModel from "../models/userModel.js";
import jwt from 'jsonwebtoken'
import bcryptjs from 'bcryptjs';
import validator from 'validator'


//Login  user


export const loginUser = async(req,res)=>{
    const {email, password} = req.body

    try {
        const user = await userModel.findOne({email})

        if(!user){
            return res.json({
                success:false,
                message:"User is not exist"
            })
        }
        const isMatch = bcryptjs.compareSync(password,user.password)

        if(!isMatch){
            return res.json({
                success:false,
                message:"Invalid credentials"
            })
        }
        const token = createToken(user._id)
        res.json({success:true,token})
        
    } catch (error) {
        console.log(error)
        res.json({
            success:false,
            message:"Error"
        })
    }
}

//create token

const createToken = (id)=>{
    return jwt.sign({id},process.env.jwt_token)
}

//Register User

export const registerUser = async(req,res)=>{
    const {name, email, password} = req.body
    try {

        // check condition for user is valid for login or not

        const exists = await userModel.findOne({email})
        if(exists){
            return res.json({
                success:false,
                message:"User already exist please login"
            })
        }
        if(!validator.isEmail(email)){
            return res.json({
                success:false,
                message:"Please enter valid email"
            })
        }
        if(password.length<8){
            return res.json({
                success:false,
                message:"Please enter strong password"
            })
        }
     //hashing Password

        
        const hashePassword =bcryptjs.hashSync(password, 10);

        const newUser = new userModel({
            name:name,
            email:email,
            password:hashePassword
        })
        const user = await newUser.save()
        const token = createToken(user._id)
        res.json({success:true , token})

    } catch (error) {
        console.log(error)
        res.json({
            success:true,
            message:"Error"
        })
    }
}
