import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, RefType } from 'mongoose';
import { UsersService } from 'src/users/users.service';
import { CreateProjectDto } from './dto/create-project.dto';
import { UpdateProjectDto } from './dto/update-project.dto';
import { Rights } from './enums/rights.enum';
import { Project, ProjectDocument } from './project.schema';

@Injectable()
export class ProjectsService {
  constructor(
    @InjectModel(Project.name) private projectModel: Model<ProjectDocument>,
    private readonly userService: UsersService,
  ) {}

  create(createProjectDto: CreateProjectDto) {
    return this.projectModel.create(createProjectDto);
  }

  findAll() {
    return this.projectModel
      .find({})
      .populate({ path: 'users.user', model: 'User' });
  }

  findById(id: RefType) {
    return this.projectModel
      .findById(id)
      .populate({ path: 'users.user', model: 'User' });
  }

  async removeUserFromProject(project: ProjectDocument, user) {
    project.removeUser(user);
    return this.findById(project.id);
  }

  async updateUserRights(
    project: ProjectDocument,
    user: string,
    rights: Rights[],
  ) {
    await this.userService.findById(user);
    await project.addUser(user);
    await project.updateOne(
      {
        $set: {
          'users.$[element].rights': rights,
        },
      },
      { arrayFilters: [{ 'element.user': user }] },
    );
    return this.findById(project.id);
  }
}
