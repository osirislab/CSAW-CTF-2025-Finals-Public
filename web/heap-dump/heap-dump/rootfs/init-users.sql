-- Create produser role
CREATE ROLE produser WITH LOGIN PASSWORD '98yui3hkjrqfaed98y9q0uo';

-- Grant read-only access
GRANT CONNECT ON DATABASE totallyhidden TO produser;
GRANT USAGE ON SCHEMA public TO produser;
