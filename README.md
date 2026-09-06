# Sakuda API

Temp number monitoring API with key authentication and admin dashboard.

## Features

- **API Key Authentication**: Secure access with unique API keys
- **Admin Dashboard**: Manage API keys and access control
- **Key Documentation**: Add documentation for each key
- **Usage Tracking**: Monitor API key usage
- **Expiration Support**: Set optional expiration dates for keys
- **Proxy Functionality**: Proxies to existing Veriflow API

## Admin Credentials

- **Email**: saqibsarwar@cc.cc
- **Password**: Biscoe@@3

## API Endpoints

### Public Endpoints (with API Key)

All API endpoints require a valid API key passed as `?key=YOUR_KEY` parameter:

- `GET /api/{dbCode}/devices?key=YOUR_KEY` - Get online devices
- `GET /api/{dbCode}/messages/{clientId}?key=YOUR_KEY` - Get messages for device

### Admin Endpoints

- `GET /admin` - Admin dashboard
- `POST /api/login` - Login to get JWT token
- `GET /api/keys` - List all API keys (requires admin JWT)
- `PUT /api/keys` - Create new API key (requires admin JWT)
- `DELETE /api/keys/{key}` - Delete API key (requires admin JWT)

## Setup

1. Install dependencies:
```bash
npm install
```

2. Set environment variables:
```bash
JWT_SECRET=your-secret-key
```

3. Deploy to Vercel:
```bash
vercel --prod
```

## Usage

### Access Admin Dashboard

1. Go to `https://your-domain.vercel.app/admin`
2. Login with admin credentials
3. Create API keys with documentation
4. Share keys with authorized users

### Use API

Clients use the API by including their key:

```bash
curl "https://sakuda-api.vercel.app/api/101/devices?key=YOUR_API_KEY"
```

## Security Features

- Bcrypt password hashing
- JWT token authentication for admin
- API key validation
- Usage tracking
- Key expiration support
- CORS enabled

## License

Built with permission from API owner for legitimate temp number monitoring purposes.