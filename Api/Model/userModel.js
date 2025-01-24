const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        require: [true , "Please tell your name"]
    },
    email: {
        type: String,
        required: [ true , " Please enter ypu email"],
        unique: true,
        lowecase: true
    },
    role: {
        type: String,
        enum: ["user" , "admin"],
        default: "user"
    },
    password: {
        type: String,
        require: [true , "Please provide a password"]
    },
    passwordConfirm: {
        type: String,
        require: [true , "Please confirm your password"],
        validate: {
            validator: function(el){
                return el === this.password 
            },
            message: "Password are not same!" 
        }
    }

})

userSchema.pre("save" , async function (next){
    // only run this function if password was actually modified 
    if (!this.isModified("password"))
    return next()

    // hash the password with cost of 12
    this.password = await bcrypt.hash(this.password , 12)

    // Delete password confirm field - cause we dont want to save the confirm password
    this.passwordConfirm = undefined
    next()


})

userSchema.pre("save" , async function (next){
    if(!this.isModified("password") || this.isNew)
    return next()

    this.passwordChangedAt = Date.now() - 1000
    next()
})

userSchema.pre(/^find/ , function (next){
    // this points to the current query
    this.find({active: {$ne: false}})
    next()
})

userSchema.method.correctPassword = async function(candidatePassword,userPassword){
    return await bcrypt.compare(candidatePassword , userPassword)
}


userSchema.methods.changePasswordAfter = function (JWTTimestamp){
    if(this.passwordChangedAt){
        const changedTimestamp = parseInt(
            this.passwordChangedAt.getTime()/1000,10
        )
        return JWTTimestamp < changedTimestamp
    }
        // false means not changed
    return false
}

const User = mongoose.model("User" , userSchema)

module.exports = User



 