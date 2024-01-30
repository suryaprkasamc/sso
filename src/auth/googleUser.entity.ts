import { Entity, Column, PrimaryGeneratedColumn, Unique } from 'typeorm';

@Entity()
export class googleUserEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  sub: string;

  @Column()
  name: string;

  @Column()
  givenName: string;

  @Column()
  familyName: string;

  @Column()
  picture: string;

  @Column()
  email: string;

  @Column()
  emailVerified: boolean;

  @Column()
  locale: string;

  @Column()
  hd: string;
}
