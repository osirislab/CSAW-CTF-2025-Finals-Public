# Use the official nginx image
FROM nginx:alpine

# Remove default nginx index
RUN rm /usr/share/nginx/html/*

# Copy your index.html into nginx's html directory
COPY index.html /usr/share/nginx/html/index.html

# Expose port 80
EXPOSE 80

# Start nginx in foreground
CMD ["nginx", "-g", "daemon off;"]
