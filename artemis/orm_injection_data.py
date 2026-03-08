# ORM-specific and NoSQL-specific error messages used by orm_injection_detector.
# These are distinct from SQL error messages in sql_injection_data.py, which covers
# raw SQL drivers. These messages are emitted by ORM frameworks and NoSQL databases.

ORM_ERROR_MESSAGES = [
    # --- Hibernate / JPA (Java) ---
    # Triggered when HQL/JPQL query syntax is invalid after injection
    "QuerySyntaxException",
    "org\\.hibernate\\.exception\\.SQLGrammarException",
    "org\\.hibernate\\.hql\\.internal\\.ast\\.QuerySyntaxException",
    "org\\.hibernate\\.QueryException",
    "Named value .{0,100}? not found in query",
    "HQL query could not be parsed",
    "antlr\\.NoViableAltException",
    "antlr\\.MismatchedTokenException",
    # Triggered by JPA EntityManager
    "javax\\.persistence\\.PersistenceException",
    "jakarta\\.persistence\\.PersistenceException",
    # --- Doctrine (PHP) ---
    "Doctrine\\\\DBAL\\\\Exception",
    "Doctrine\\\\ORM\\\\Query\\\\QueryException",
    "[Syntax Error]",
    "Expected .{0,150}?, got .{0,150}?'",
    "Doctrine\\\\ORM\\\\QueryBuilder",
    # --- Django ORM (Python) ---
    # Django re-raises DB errors with its own wrapper
    "django\\.db\\.utils\\.OperationalError",
    "django\\.db\\.utils\\.ProgrammingError",
    "django\\.db\\.utils\\.DataError",
    # --- SQLAlchemy (Python) ---
    "sqlalchemy\\.exc\\.OperationalError",
    "sqlalchemy\\.exc\\.ProgrammingError",
    "sqlalchemy\\.exc\\.StatementError",
    # --- Laravel Eloquent / Active Record (PHP/Ruby) ---
    "Illuminate\\\\Database\\\\QueryException",
    "ActiveRecord::StatementInvalid",
    "PG::SyntaxError",
    # --- MongoDB / NoSQL ---
    "MongoServerError",
    "MongoError",
    "E11000 duplicate key error",
    "\\$where is not allowed",
    "no such operator: \\$",
    "unknown operator: \\$",
    "unknown top level operator: \\$",
    # Mongoose (Node.js) validation and cast errors
    "Cast to .{0,50}? failed for value",
    "Mongoose.{0,100}?Error",
    "ValidatorError",
    "ValidationError",
    # --- Prisma (Node.js) ---
    "PrismaClientKnownRequestError",
    "PrismaClientValidationError",
    "PrismaClientUnknownRequestError",
    # --- Sequelize (Node.js) ---
    "SequelizeDatabaseError",
    "SequelizeValidationError",
    # --- Gorm (Go) ---
    "gorm\\.io/gorm",
]

# NoSQL operator injection payloads.
# These are submitted as URL query parameters in two forms:
#   - PHP/Express bracket syntax:  param[$ne]=1
#   - Raw value injection:         param={"$ne": ""}
# They probe for MongoDB-style operator injection where user input
# reaches a NoSQL query without sanitisation.
NOSQL_OPERATOR_PAYLOADS = [
    # Bracket-style (Apache, PHP, Express, etc.)
    "[$ne]=1",
    "[$gt]=",
    "[$nin][]=",
    "[$regex]=.*",
    # JSON object style — for param=<value> where value reaches JSON.parse
    '][',
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "sleep(1)"}',
]
