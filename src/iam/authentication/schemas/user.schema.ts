import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { Role } from '../../enums/role.enum';

export type UserDocument = HydratedDocument<User>;

@Schema()
export class User {
  @Prop({ unique: true, sparse: true }) provisioningRequestId?: string;
  @Prop() provisioningActor?: string;

  @Prop({
    required: true,
    unique: true,
    lowercase: true,
  })
  email: string;

  // Provider-only accounts have no password and cannot use password login.
  @Prop()
  password?: string;

  @Prop({ type: [String], default: undefined })
  externalIdentities?: string[];

  @Prop({
    immutable: true,
    default: () => Date.now(),
  })
  createdAt: Date;

  @Prop({ default: () => Date.now() })
  updatedAt: Date;

  @Prop({ type: String, default: () => Role.Regular })
  role: Role;
}

export const UserSchema = SchemaFactory.createForClass(User);

// Each provider subject belongs to exactly one local UUID. The array is omitted
// on password accounts so this sparse multikey index ignores those accounts.
UserSchema.index({ externalIdentities: 1 }, { unique: true, sparse: true });
