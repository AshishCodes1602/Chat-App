import bcrypt from "bcryptjs/dist/bcrypt.js";
import User from "../models/user.model.js";
import generatetokenandsetcookie from "../utils/generateToken.js";

export const signup = async (req, res) => {
    try {
        const {fullName,username,password,confirmPassword,gender} = req.body;
        
        if(password !== confirmPassword) {
            return res.status(400).json({error: "Passwords don't match"})
        }

        const user = await User.findOne({ username });

        if(user) {
            return res.status(400).json({error: "Username already exists"})
        }
        else{
            console.log("creating new user");
        }

        //HASH PASSWORD
        const salt = await bcrypt.genSalt(10);
        const hashedpassword = await bcrypt.hash(password, salt);

        const boyprofilepic = `https://avatar.iran.liara.run/public/boy?username=${username}`
        const girlprofilepic = `https://avatar.iran.liara.run/public/girl?username=${username}`

        const newUser = new User({
            fullName,
            username,
            password: hashedpassword,
            gender,
            profilepic: gender === "male" ? boyprofilepic : girlprofilepic 
        }) 

        if(newUser) {
            // Generate JWT token
            generatetokenandsetcookie(newUser._id, res)
            await newUser.save()

            res.status(201).json({
                _id: newUser._id,
                fullName: newUser.fullName,
                username: newUser.username,
                profilepic: newUser.profilepic
            });

        } else {
            res.status(400).json({ error: "Invalid user data"});
        }
        

    } catch (error) {
        console.log("Error in signup controller", error.message)
        res.status(500).json({error: "Internal server error"})
    }
};

export const login = async (req, res) => {
    
    try {
        const {username, password} = req.body
        const user = await User.findOne({ username })
        const isPasswordcorrect = await bcrypt.compare(password, user?.password || "") 

        console.log(user)

        if(!user || !isPasswordcorrect) {
            return res.status(400).json({error : "Invalid username or password"})
        }

        generatetokenandsetcookie(user._id, res)

        res.status(200).json({
            _id: user._id,
            fullName: user.fullName,
            username: user.username,
            profilepic: user.profilepic
        })

    } catch (error) {
        console.log("Error in signup controller", error.message)
        res.status(500).json({error: "Internal server error"})
    }
}

export const logout = (req, res) => {
    try {
        res.cookie("jwt", "", {maxAge: 0});
        res.status(200).json({message: "Logged out successful"});
    } catch (error) {
        console.log("Error in signup controller", error.message)
        res.status(500).json({error: "Internal server error"})
    }
}