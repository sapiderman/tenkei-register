-- Faculty and major: free-text academic affiliation, required for members of
-- the Tenkei Universitas Indonesia campus dojo (enforced in application code
-- via types.FacultyMajorMissing), optional elsewhere.
ALTER TABLE users ADD COLUMN IF NOT EXISTS "faculty" varchar(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS "major" varchar(100);

-- Re-label the campus dojo to the canonical spelling. The university brands
-- itself "Universitas Indonesia" in every language; the registration form is
-- corrected to match in the same release, so the rule and the form agree.
UPDATE users SET dojo = 'Tenkei Universitas Indonesia' WHERE dojo = 'Tenkei University Indonesia';
