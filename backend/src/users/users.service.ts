import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, RefType } from 'mongoose';
import { User, UserDocument } from 'src/users/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async create(createUserDto: CreateUserDto): Promise<UserDocument> {
    const createdUser = new this.userModel(createUserDto);
    return await createdUser.save();
  }

  async findAll(): Promise<UserDocument[]> {
    return await this.userModel.find();
  }

  async findById(id: RefType): Promise<UserDocument> {
    const user = await this.userModel.findById(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async findByEmail(email: string): Promise<UserDocument> {
    return this.userModel.findOne({ email });
  }

  async update(
    user: UserDocument,
    update: UpdateUserDto,
  ): Promise<UserDocument> {
    const res = await user.updateOne(update);
    return res;
  }

  async remove(user: UserDocument) {
    return await user.deleteOne();
  }
}
