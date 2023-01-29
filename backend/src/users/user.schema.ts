import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Exclude } from 'class-transformer';
import { Transform } from 'class-transformer';
import { Document } from 'mongoose';
import { Role } from '../enums/role.enum';

export type UserDocument = User & Document;

@Schema()
export class User {
  @Transform(({ obj }) => obj._id.toString())
  _id: string;
  @Exclude()
  __v: number;
  @Prop({ required: true, maxlength: 32 })
  firstname: string;
  @Prop({ required: true, maxlength: 32 })
  lastname: string;
  @Prop({ required: true, unique: true, lowercase: true })
  email: string;
  @Exclude()
  @Prop({ required: true })
  password: string;
  @Prop({ required: true, default: [Role.USER] })
  roles: Array<Role>;
  @Prop({ default: Date.now() })
  createdDate: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
