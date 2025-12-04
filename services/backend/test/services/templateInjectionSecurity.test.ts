/*
  Test de mitigación de template injection

  Este test se hace cargo de valida que la vulnerabilida de template injection haya sido mitigada en la función createUser. La versión vulnerable de main, utiliza una
  interpolación de strings en el template, de esta forma una entrada maliciosa por parte del usuario podría generar un template injection.

  El test revisa que los payloads maliciosos sean rechazados y también que aquellas entradas que sean seguras sigan funcionando y sean manejadas correctamente.
*/

import AuthService from '../../src/services/authService';
import db from '../../src/db';
import { User } from '../../src/types/user';

jest.mock('../../src/db');
jest.mock('nodemailer');

describe('Security: Template Injection Mitigation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.SMTP_HOST = 'localhost';
    process.env.SMTP_PORT = '25';
    process.env.SMTP_USER = 'test';
    process.env.SMTP_PASS = 'test';
    process.env.FRONTEND_URL = 'http://localhost:3000';
  });

  /*  Caso 1: Intentar hacer un template injection mediante first_name.
        Payload: <%= 7*7 %>
  */
  it('should reject malicious first_name payload attempting template injection', async () => {
    const maliciousUser: User = {
      id: 'user-123',
      email: 'test@example.com',
      password: 'password123',
      first_name: '<%= 7*7 %>',
      last_name: 'Last',
      username: 'username'
    };

    // Mock no existing user
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    
    const mockedDbInstance = db as jest.MockedFunction<typeof db>;
    mockedDbInstance.mockReturnValue(selectChain as any);

    await expect(AuthService.createUser(maliciousUser)).rejects.toThrow('Invalid name');
  });

  /*  Caso 2: Intentar hacer un template injection mediante last_name.
        Payload: <%= global.process.exit() %>
  */
  it('should reject malicious last_name payload attempting template injection', async () => {
    const maliciousUser: User = {
      id: 'user-123',
      email: 'test@example.com',
      password: 'password123',
      first_name: 'First',
      last_name: '<%= global.process.exit() %>',
      username: 'username'
    };

    // Mock no existing user
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    
    const mockedDbInstance = db as jest.MockedFunction<typeof db>;
    mockedDbInstance.mockReturnValue(selectChain as any);

    await expect(AuthService.createUser(maliciousUser)).rejects.toThrow('Invalid name');
  });

  /*  Caso 3: Intentar hacer un template injection mediante los dos campos (first_name y last_name).
        Payload: <%= %>
  */
  it('should reject EJS tags in name fields', async () => {
    const maliciousUser: User = {
      id: 'user-123',
      email: 'test@example.com',
      password: 'password123',
      first_name: '<%=',
      last_name: '%>',
      username: 'username'
    };

    // Mock no existing user
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    
    const mockedDbInstance = db as jest.MockedFunction<typeof db>;
    mockedDbInstance.mockReturnValue(selectChain as any);

    await expect(AuthService.createUser(maliciousUser)).rejects.toThrow('Invalid name');
  });


  // Caso 4: Intentar inyectar codigo JS en los campos.
  it('should reject JavaScript code in name fields', async () => {
    const maliciousUser: User = {
      id: 'user-123',
      email: 'test@example.com',
      password: 'password123',
      first_name: '${global.process.exit()}',
      last_name: 'Last',
      username: 'username'
    };

    // Mock no existing user
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    
    const mockedDbInstance = db as jest.MockedFunction<typeof db>;
    mockedDbInstance.mockReturnValue(selectChain as any);

    await expect(AuthService.createUser(maliciousUser)).rejects.toThrow('Invalid name');
  });

  // Caso 5: Verificar que una entrada segura/sanitizada funcione
  it('should accept and safely render valid name fields', async () => {
    const safeUser: User = {
      id: 'user-123',
      email: 'safe@example.com',
      password: 'password123',
      first_name: 'John',
      last_name: 'Doe',
      username: 'johndoe'
    };

    // Mock no existing user
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };

    // Mock bcrypt
    jest.mock('bcryptjs', () => ({
      hash: jest.fn().mockResolvedValue('hashed_password')
    }));

    // Mock database insert
    const insertChain = {
      insert: jest.fn().mockReturnThis(),
      returning: jest.fn()
    };

    const mockedDbInstance = db as jest.MockedFunction<typeof db>;
    mockedDbInstance
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Mock nodemailer
    const nodemailer = require('nodemailer');
    const mockSendMail = jest.fn().mockResolvedValue({ success: true });
    nodemailer.createTransport = jest.fn().mockReturnValue({ sendMail: mockSendMail });

    await expect(AuthService.createUser(safeUser)).resolves.not.toThrow();
  });
});

