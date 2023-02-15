import * as request from 'supertest';
import { app, setUpServer, tearDownServer } from './setup.e2e-spect';

const gql = '/graphql';
export let accessToken: string;
let id: string;

describe('Authentication', () => {
  beforeAll(async () => {
    await setUpServer();
  });

  afterAll(async () => {
    await tearDownServer();
  });

  it('Registration', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .send({
        query:
          'mutation Register($user: UserInput!) {register(user: $user) {created id lastUpdated name}}',
        variables: {
          user: {
            email: 'test@test.com',
            name: 'Test',
            password: 'Test@Pass1',
            username: 'Test',
          },
        },
        operationName: 'Register',
      })
      .expect(200)
      .expect(({ body }) => {
        expect(body.data.register.name).toBe('Test');
      });
  });
  it('Login', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .send({
        operationName: null,
        variables: {},
        query:
          'query {login(login:{email: "test@test.com", password: "Test@Pass1"}) {id name accessToken}}',
      })
      .expect(200)
      .expect(({ body }) => {
        accessToken = body.data.login.accessToken;
        id = body.data.login.id;
        expect(body.data.login.name).toBe('Test');
      });
  });

  it('Login (Wrong Email)', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .send({
        operationName: null,
        variables: {},
        query:
          'query {login(login:{email: "Test", password: "test"}) {id name accessToken}}',
      })
      .expect(200)
      .expect(({ body }) => {
        expect(body.data).toBe(null);
        expect(body.errors[0].message).toBe('Invalid Username or Password');
      });
  });

  it('Get logged in user', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        operationName: null,
        variables: {},
        query: '{me {name}}',
      })
      .expect(200)
      .expect(({ body }) => {
        expect(body.data.me.name).toBe('Test');
      });
  });

  it('Get Users with no pagination', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .send({
        operationName: null,
        variables: {},
        query: '{getUsers(params: {}) {id name}}',
      })
      .expect(200)
      .expect(({ body }) => {
        expect(body?.data?.getUsers?.length).toBe(1);
      });
  });

  it('Get Users with pagination', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .send({
        operationName: null,
        variables: {},
        query:
          '{getUsers(params: {page: 1, pageSize: 100, paging: true}) {id name total}}',
      })
      .expect(200)
      .expect(({ body }) => {
        expect(body.data.getUsers[0].total).toBe(1);
      });
  });

  it('Get User', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .send({
        operationName: null,
        variables: {},
        query: `{getUser(id: ${id}) {id name created}}`,
      })
      .expect(200)
      .expect(({ body }) => {
        expect(body.data.getUser.id).toBe(id);
      });
  });

  it('Get User with ID not in system', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .send({
        operationName: null,
        variables: {},
        query: `{getUser(id: 10) {id name created}}`,
      })
      .expect(200)
      .expect(({ body }) => {
        expect(body.data).toBe(null);
      });
  });

  it('Update User (Without Authorization)', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .send({
        operationName: null,
        variables: {},
        query: 'mutation{updateUser(user: {name: "Changed Name"}) {name}}',
      })
      .expect(200)
      .expect(({ body }) => {
        expect(body.data).toBe(null);
        expect(body.errors).toBeDefined();
      });
  });
  it('Update User (With Authorization)', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        operationName: null,
        variables: {},
        query: 'mutation{updateUser(user: {name: "Changed Name"}) {name}}',
      })
      .expect(200)
      .expect(({ body }) => {
        expect(body.data.updateUser.name).toBe('Changed Name');
        expect(body.errors).toBeUndefined();
      });
  });

  it('Get logged in user', async () => {
    return request(app.getHttpServer())
      .post(gql)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        operationName: null,
        variables: {},
        query: '{me {name id accessToken}}',
      })
      .expect(200)
      .expect(({ body }) => {
        expect(body.data.me.name).toBe('Changed Name');
      });
  });
});
