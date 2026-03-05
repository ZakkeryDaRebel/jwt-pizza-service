# Build this code by calling `chmod +x generatePizzaData.sh`
# Run with ./generatePizzaData.sh <host>

# Check if host is provided as a command line argument
if [ -z "$1" ]; then
  echo "Usage: $0 <host>"
  echo "Example: $0 http://localhost:3000"
  exit 1
fi
host=$1

response=$(curl -s -X PUT $host/api/auth -d '{"email":"a@jwt.com", "password":"admin"}' -H 'Content-Type: application/json')
token=$(echo $response | jq -r '.token')

# Add users
curl -X POST $host/api/auth -d '{"name":"pizza diner", "email":"d@jwt.com", "password":"diner"}' -H 'Content-Type: application/json'
curl -X POST $host/api/auth -d '{"name":"pizza franchisee", "email":"f@jwt.com", "password":"franchisee"}' -H 'Content-Type: application/json'

curl -X POST $host/api/auth -d '{"name":"user1", "email":"u1@jwt.com", "password":"user1"}' -H 'Content-Type: application/json'
curl -X POST $host/api/auth -d '{"name":"user2", "email":"u2@jwt.com", "password":"user2"}' -H 'Content-Type: application/json'
curl -X POST $host/api/auth -d '{"name":"user3", "email":"u3@jwt.com", "password":"user3"}' -H 'Content-Type: application/json'
curl -X POST $host/api/auth -d '{"name":"user4", "email":"u4@jwt.com", "password":"user4"}' -H 'Content-Type: application/json'
curl -X POST $host/api/auth -d '{"name":"user5", "email":"u5@jwt.com", "password":"user5"}' -H 'Content-Type: application/json'
curl -X POST $host/api/auth -d '{"name":"user6", "email":"u6@jwt.com", "password":"user6"}' -H 'Content-Type: application/json'
curl -X POST $host/api/auth -d '{"name":"user7", "email":"u7@jwt.com", "password":"user7"}' -H 'Content-Type: application/json'
curl -X POST $host/api/auth -d '{"name":"user8", "email":"u8@jwt.com", "password":"user8"}' -H 'Content-Type: application/json'
curl -X POST $host/api/auth -d '{"name":"user9", "email":"u9@jwt.com", "password":"user9"}' -H 'Content-Type: application/json'
curl -X POST $host/api/auth -d '{"name":"user10", "email":"u10@jwt.com", "password":"user10"}' -H 'Content-Type: application/json'

# Add menu
curl -X PUT $host/api/order/menu -H 'Content-Type: application/json' -d '{ "title":"Veggie", "description": "A garden of delight", "image":"pizza1.png", "price": 0.0038 }'  -H "Authorization: Bearer $token"
curl -X PUT $host/api/order/menu -H 'Content-Type: application/json' -d '{ "title":"Pepperoni", "description": "Spicy treat", "image":"pizza2.png", "price": 0.0042 }'  -H "Authorization: Bearer $token"
curl -X PUT $host/api/order/menu -H 'Content-Type: application/json' -d '{ "title":"Margarita", "description": "Essential classic", "image":"pizza3.png", "price": 0.0042 }'  -H "Authorization: Bearer $token"
curl -X PUT $host/api/order/menu -H 'Content-Type: application/json' -d '{ "title":"Crusty", "description": "A dry mouthed favorite", "image":"pizza4.png", "price": 0.0028 }'  -H "Authorization: Bearer $token"
curl -X PUT $host/api/order/menu -H 'Content-Type: application/json' -d '{ "title":"Charred Leopard", "description": "For those with a darker side", "image":"pizza5.png", "price": 0.0099 }'  -H "Authorization: Bearer $token"

# Add franchise and store
curl -X POST $host/api/franchise -H 'Content-Type: application/json' -d '{"name": "pizzaPocket", "admins": [{"email": "f@jwt.com"}]}'  -H "Authorization: Bearer $token"
curl -X POST $host/api/franchise/1/store -H 'Content-Type: application/json' -d '{"franchiseId": 1, "name":"SLC"}'  -H "Authorization: Bearer $token"

echo "Database data generated"