import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  ValidationPipe,
} from '@nestjs/common';
import { UseInterceptors } from '@nestjs/common/decorators/core/use-interceptors.decorator';
import { ParseObjectIdPipe } from 'src/shared/pipes/objectid.pipe';
import MongooseClassSerializerInterceptor from 'src/shared/utils/mongoSerializeInterceptor';
import { AddUserDto } from './dto/add-user.dto';
import { CreateProjectDto } from './dto/create-project.dto';
import { UpdateProjectDto } from './dto/update-project.dto';
import { ProjectByIdPipe } from './pipes/project-by-id.pipe';
import { Project, ProjectDocument } from './project.schema';
import { ProjectsService } from './projects.service';

@UseInterceptors(MongooseClassSerializerInterceptor(Project))
@Controller('projects')
export class ProjectsController {
  constructor(private readonly projectsService: ProjectsService) {}

  @Post()
  create(@Body(ValidationPipe) createProjectDto: CreateProjectDto) {
    return this.projectsService.create(createProjectDto);
  }

  @Get()
  findAll() {
    return this.projectsService.findAll();
  }

  @Get(':id')
  findOne(@Param('id', ProjectByIdPipe) project: ProjectDocument) {
    return project;
  }

  @Post(':id/users')
  addUser(
    @Param('id', ProjectByIdPipe) project: ProjectDocument,
    @Body(ValidationPipe) data: AddUserDto,
  ) {
    return this.projectsService.updateUserRights(
      project,
      data.userId,
      data.rights,
    );
  }

  @Delete(':id/users')
  removeUser(
    @Param('id', ProjectByIdPipe) project: ProjectDocument,
    @Body('userId', ParseObjectIdPipe) user: string,
  ) {
    return this.projectsService.removeUserFromProject(project, user);
  }
}
