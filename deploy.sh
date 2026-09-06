#!/bin/bash

echo "🚀 Deploying Sakuda API and Frontend to Vercel..."

# Deploy API
echo "📦 Deploying API..."
cd /home/workspace/Projects/sakuda-api
vercel --prod --yes

# Deploy Frontend
echo "🎨 Deploying Frontend..."
cd /home/workspace/Projects/sakuda-frontend
vercel --prod --yes

echo "✅ Deployment complete!"
echo "🔗 API URL: https://sakuda-api.vercel.app"
echo "🔗 Frontend URL: https://sakuda-frontend.vercel.app"
echo "🔗 Admin Dashboard: https://sakuda-api.vercel.app/admin"