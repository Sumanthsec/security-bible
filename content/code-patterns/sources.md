# Sources

## HTTP Request Input — Where User Data Enters the Application

### Python/Flask
| Source | Description |
|--------|-------------|
| `request.args.get('param')` | URL query parameters (`?param=value`) |
| `request.form['param']` | POST form body |
| `request.json` | JSON request body |
| `request.headers.get('X-Header')` | HTTP headers |
| `request.cookies.get('name')` | Cookies |

### Python/Django
| Source | Description |
|--------|-------------|
| `request.GET['param']` | URL query parameters |
| `request.POST['param']` | POST form body |
| `request.body` | Raw request body |
| `request.META['HTTP_X_HEADER']` | HTTP headers |

### Java/Spring
| Source | Description |
|--------|-------------|
| `@RequestParam String param` | URL query or form parameter |
| `@PathVariable String id` | URL path segment (`/users/{id}`) |
| `@RequestBody Object body` | JSON/XML request body |
| `@RequestHeader String header` | HTTP header |
| `@CookieValue String cookie` | Cookie value |
| `request.getParameter("param")` | Servlet API — query or form parameter |

### Node.js/Express
| Source | Description |
|--------|-------------|
| `req.query.param` | URL query parameters |
| `req.body.param` | POST body (requires body-parser) |
| `req.params.param` | URL path parameters (`/users/:id`) |
| `req.headers['x-header']` | HTTP headers |
| `req.cookies.name` | Cookies (requires cookie-parser) |

### PHP
| Source | Description |
|--------|-------------|
| `$_GET['param']` | URL query parameters |
| `$_POST['param']` | POST form body |
| `$_REQUEST['param']` | GET + POST + COOKIE combined |
| `$_COOKIE['name']` | Cookies |
| `$_SERVER['HTTP_X_HEADER']` | HTTP headers |
| `file_get_contents('php://input')` | Raw request body |
