# API Reference

The management API runs on `api_addr` (default `:8443`) and provides REST endpoints for policy management, logs, and cluster operations.

## Authentication

When `api_key` is set in the config, all endpoints (except health) require:

```
Authorization: Bearer <api_key>
# or
X-API-Key: <api_key>
```

## Endpoints

### Health

```
GET /health
```

Returns `200 OK` when the API is running. No authentication required.

### Policies

```
GET    /api/policies          # List all policy rules
POST   /api/policies          # Create a new rule
PUT    /api/policies/:id      # Update a rule
DELETE /api/policies/:id      # Delete a rule
```

### DLP Rules

```
GET    /api/dlp               # List DLP rules
POST   /api/dlp               # Create a DLP rule
PUT    /api/dlp/:id           # Update a DLP rule
DELETE /api/dlp/:id           # Delete a DLP rule
```

### Logs

```
GET /api/logs                 # Query request logs
GET /api/logs?limit=100       # With pagination
```

### Categories

```
GET  /api/categories          # List domain categories
POST /api/categories/import   # Bulk import categorized domains
```

### Threat Intelligence

```
GET /api/threat/stats         # Threat detection statistics
```

### Statistics

```
GET /api/stats                # Proxy runtime statistics
```

### Nodes (multi-node)

```
GET    /api/nodes             # List registered nodes
POST   /api/nodes             # Register a new node
DELETE /api/nodes/:id         # Remove a node
```

### CA Certificate

```
GET /api/ca                   # Download the CA certificate
```

### Configuration

```
GET /api/config               # View current running config
```
