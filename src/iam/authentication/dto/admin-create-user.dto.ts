import { IsEnum, IsUUID, MinLength } from 'class-validator';
import { Role } from '../../enums/role.enum';
import { UserAuthDto } from './user-auth.dto';
export class AdminCreateUserDto extends UserAuthDto {
  @MinLength(12) declare password: string;
  @IsEnum(Role) role: Role;
  @IsUUID('4') requestId: string;
}
