-- Create the vendors table with a relation to cve_simple (by cve_id)
CREATE TABLE IF NOT EXISTS vendors (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL,
    vendor_name TEXT NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES cve_simple(cve_id) ON DELETE CASCADE
);
