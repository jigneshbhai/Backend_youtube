import mongoose, { Schema } from "mongoose";
import  jwt  from "jsonwebtoken";
import bcrypt from "bcrypt"



const userSchema = new Schema(
  {
    username: {
      type: String,
      require: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    email: {
      type: String,
      require: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    fullName: {
      type: String,
      require: true,
      trim: true,
      index: true,
    },
    avatar: {
      type: String,
      require: true,
    },
    coverImage: {
      type: String,
    },
    watchHistory: [
      {
        type: Schema.Types.ObjectId,
        ref: "Video",
      },
    ],
    password: {
      type: String,
      require: [true, "Password is require"],
    },
    refreshToken: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

//encryption of password

userSchema.pre("save", async function (next) {
    if(!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 10)
    next()
})

//custom method check correct password

userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
      {
        _id: this._id,
      },
      process.env.REFRESH_TOKEN,
      {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRY, 
      }
    );
}

userSchema.methods.generateAccessToken = function () {
     return jwt.sign(
       {
         _id: this._id,
         email: this.email,
         username: this.username,
         fullName: this.fullName,
       },
       process.env.JWT_SECRET,
       {
         expiresIn: process.env.JWT_SECRET_EXPIRY,
       }
     );
};

export const User = mongoose.model("User", userSchema);
