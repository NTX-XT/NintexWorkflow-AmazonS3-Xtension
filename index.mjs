// AWS S3 Lambda Function for Nintex Workflow Xtension
// Compatible with AWS Lambda Node.js 18.x or higher

import { 
    S3Client, 
    PutObjectCommand, 
    GetObjectCommand,
    DeleteObjectCommand,
    DeleteObjectsCommand,
    ListObjectsV2Command,
    CreateBucketCommand,
    ListBucketsCommand,
    HeadObjectCommand,
    CopyObjectCommand
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import crypto from 'crypto';

// Configuration from environment variables
const CONFIG = {
    ALLOWED_BUCKETS: process.env.ALLOWED_BUCKETS?.split(',').filter(b => b) || [],
    MAX_FILE_SIZE: parseInt(process.env.MAX_FILE_SIZE) || 52428800, // 50MB default
    DEFAULT_REGION: process.env.DEFAULT_REGION || process.env.AWS_REGION || '<your-region ex. "us-east-2">',
    ENABLE_LOGGING: process.env.ENABLE_LOGGING === 'true',
    ENCRYPTION_TYPE: process.env.ENCRYPTION_TYPE || 'AES256',
    PRESIGNED_URL_EXPIRY: parseInt(process.env.PRESIGNED_URL_EXPIRY) || 3600,
    RATE_LIMIT_ENABLED: process.env.RATE_LIMIT_ENABLED === 'true',
    RATE_LIMIT_REQUESTS: parseInt(process.env.RATE_LIMIT_REQUESTS) || 100,
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 60000 // 1 minute
};

// CORS headers for Nintex compatibility
const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Amz-Date, X-Api-Key, X-Amz-Security-Token",
    "Access-Control-Max-Age": "86400",
    "Content-Type": "application/json"
};

// Rate limiting map (in-memory for Lambda)
const rateLimitMap = new Map();

// Blocked file extensions for security
const BLOCKED_EXTENSIONS = ['exe', 'bat', 'cmd', 'scr', 'com', 'pif', 'vbs', 'js', 'jar', 'msi', 'app', 'deb', 'rpm'];

// Main handler function
export const handler = async (event, context) => {
    // Handle preflight OPTIONS requests
    if (event.requestContext?.http?.method === "OPTIONS") {
        return {
            statusCode: 200,
            headers: corsHeaders,
            body: JSON.stringify({ message: "CORS preflight successful" })
        };
    }

    let requestId = context.requestId;
    
    try {
        // Log incoming request if enabled
        if (CONFIG.ENABLE_LOGGING) {
            console.log(`Request ID: ${requestId}`, {
                path: event.requestContext?.http?.path,
                method: event.requestContext?.http?.method,
                sourceIp: event.requestContext?.http?.sourceIp
            });
        }

        // Extract and validate credentials
        const credentials = extractCredentialsFromAuth(event);
        
        // Check rate limiting if enabled
        if (CONFIG.RATE_LIMIT_ENABLED) {
            checkRateLimit(credentials.accessKey);
        }

        // Route to appropriate handler
        const path = event.requestContext?.http?.path || event.rawPath || '';
        const handler = getHandler(path);
        
        if (!handler) {
            return createResponse(404, {
                error: "Endpoint not found",
                availableEndpoints: getAvailableEndpoints()
            });
        }

        // Execute handler with credentials
        const result = await handler(event, credentials);
        
        // Add request ID to successful responses
        if (result.body) {
            const body = JSON.parse(result.body);
            body.requestId = requestId;
            result.body = JSON.stringify(body);
        }
        
        return result;

    } catch (error) {
        console.error(`Error in request ${requestId}:`, error);
        return handleError(error, requestId);
    }
};

// Route handler mapping
function getHandler(path) {
    const handlers = {
        '/amazon-s3-upload': handleAmazonS3Upload,
        '/create-bucket': handleCreateBucket,
        '/create-folder': handleCreateFolder,
        '/create-object': handleCreateObject,
        '/delete-file': handleDeleteFile,
        '/delete-folder': handleDeleteFolder,
        '/get-object': handleGetObject,
        '/list-buckets': handleListBuckets,
        '/list-files': handleListFiles,
        '/list-folder-contents': handleListFolderContents,
        '/batch-delete': handleBatchDelete,
        '/copy-object': handleCopyObject,
        '/get-presigned-url': handleGetPresignedUrl,
        '/check-object-exists': handleCheckObjectExists
    };

    for (const [endpoint, handler] of Object.entries(handlers)) {
        if (path.includes(endpoint)) {
            return handler;
        }
    }
    
    return null;
}

// Get available endpoints
function getAvailableEndpoints() {
    return [
        "/amazon-s3-upload - Upload file to S3",
        "/create-bucket - Create new S3 bucket",
        "/create-folder - Create folder in bucket",
        "/create-object - Create object in bucket",
        "/delete-file - Delete file from bucket",
        "/delete-folder - Delete folder and contents",
        "/get-object - Retrieve object content",
        "/list-buckets - List all accessible buckets",
        "/list-files - List files in bucket",
        "/list-folder-contents - List folder contents",
        "/batch-delete - Delete multiple files",
        "/copy-object - Copy object within S3",
        "/get-presigned-url - Get temporary download/upload URL",
        "/check-object-exists - Check if object exists"
    ];
}

// Extract AWS credentials from Basic Auth header
function extractCredentialsFromAuth(event) {
    const authHeader = event.headers?.authorization || event.headers?.Authorization;
    
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        throw new AuthenticationError('Missing or invalid Authorization header. Expected Basic authentication with AWS Access Key as username and Secret Key as password.');
    }
    
    try {
        const encodedCredentials = authHeader.substring(6);
        const decodedCredentials = Buffer.from(encodedCredentials, 'base64').toString('utf-8');
        const [accessKey, secretKey] = decodedCredentials.split(':');
        
        if (!accessKey || !secretKey) {
            throw new AuthenticationError('Invalid credentials format. Use AWS Access Key ID as username and Secret Access Key as password.');
        }
        
        // Basic validation of AWS credential format
        if (!accessKey.match(/^[A-Z0-9]{16,128}$/)) {
            throw new AuthenticationError('Invalid AWS Access Key ID format');
        }
        
        return { accessKey, secretKey };
    } catch (error) {
        if (error instanceof AuthenticationError) throw error;
        throw new AuthenticationError('Failed to parse credentials from Authorization header');
    }
}

// Rate limiting implementation
function checkRateLimit(identifier) {
    const now = Date.now();
    const userRequests = rateLimitMap.get(identifier) || [];
    
    // Clean old requests outside the window
    const recentRequests = userRequests.filter(time => now - time < CONFIG.RATE_LIMIT_WINDOW);
    
    if (recentRequests.length >= CONFIG.RATE_LIMIT_REQUESTS) {
        throw new RateLimitError(`Rate limit exceeded. Maximum ${CONFIG.RATE_LIMIT_REQUESTS} requests per ${CONFIG.RATE_LIMIT_WINDOW/1000} seconds.`);
    }
    
    recentRequests.push(now);
    rateLimitMap.set(identifier, recentRequests);
    
    // Clean up old entries to prevent memory leak
    if (rateLimitMap.size > 1000) {
        const oldestAllowed = now - CONFIG.RATE_LIMIT_WINDOW;
        for (const [key, requests] of rateLimitMap.entries()) {
            const validRequests = requests.filter(time => time > oldestAllowed);
            if (validRequests.length === 0) {
                rateLimitMap.delete(key);
            } else {
                rateLimitMap.set(key, validRequests);
            }
        }
    }
}

// Parse request body with validation
function parseRequestBody(event) {
    try {
        if (!event.body) {
            return {};
        }
        return JSON.parse(event.body);
    } catch (error) {
        throw new ValidationError('Invalid JSON in request body');
    }
}

// Create S3 client with credentials
function createS3Client(credentials, region) {
    return new S3Client({
        region: region || CONFIG.DEFAULT_REGION,
        credentials: {
            accessKeyId: credentials.accessKey,
            secretAccessKey: credentials.secretKey
        },
        maxAttempts: 3,
        requestHandler: {
            connectionTimeout: 5000,
            socketTimeout: 60000
        }
    });
}

// Validate file for upload
function validateFile(fileName, fileContent) {
    // Path traversal check
    if (fileName.includes('..') || fileName.includes('\\') || fileName.startsWith('/')) {
        return {
            isValid: false,
            error: "Invalid file name - path traversal attempts not allowed"
        };
    }

    // Check file extension
    const fileExtension = fileName.split('.').pop()?.toLowerCase();
    if (fileExtension && BLOCKED_EXTENSIONS.includes(fileExtension)) {
        return {
            isValid: false,
            error: `File type '.${fileExtension}' is not allowed for security reasons`
        };
    }

    // Validate file size
    try {
        const fileBuffer = Buffer.from(fileContent, 'base64');
        if (fileBuffer.length > CONFIG.MAX_FILE_SIZE) {
            return {
                isValid: false,
                error: `File size ${(fileBuffer.length / 1048576).toFixed(2)}MB exceeds maximum allowed size of ${(CONFIG.MAX_FILE_SIZE / 1048576).toFixed(2)}MB`
            };
        }
        
        return { isValid: true, buffer: fileBuffer };
    } catch (error) {
        return {
            isValid: false,
            error: "Invalid file content encoding (expected base64)"
        };
    }
}

// Validate bucket access
function validateBucketAccess(bucketName) {
    if (CONFIG.ALLOWED_BUCKETS.length > 0 && !CONFIG.ALLOWED_BUCKETS.includes(bucketName)) {
        throw new ValidationError(`Access to bucket '${bucketName}' is not allowed`);
    }
}

// 1. Amazon S3 Upload Handler
async function handleAmazonS3Upload(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, fileName, fileContent, contentType, region, metadata, tags } = data;

    if (!bucketName || !fileName || !fileContent) {
        throw new ValidationError("Missing required fields: bucketName, fileName, fileContent");
    }

    validateBucketAccess(bucketName);
    
    const validation = validateFile(fileName, fileContent);
    if (!validation.isValid) {
        throw new ValidationError(validation.error);
    }

    const s3Client = createS3Client(credentials, region);
    
    const uploadParams = {
        Bucket: bucketName,
        Key: fileName,
        Body: validation.buffer,
        ContentType: contentType || 'application/octet-stream',
        ServerSideEncryption: CONFIG.ENCRYPTION_TYPE
    };

    // Add metadata if provided
    if (metadata && typeof metadata === 'object') {
        uploadParams.Metadata = metadata;
    }

    // Add tags if provided
    if (tags && typeof tags === 'object') {
        uploadParams.Tagging = Object.entries(tags)
            .map(([key, value]) => `${key}=${value}`)
            .join('&');
    }

    const result = await s3Client.send(new PutObjectCommand(uploadParams));

    if (CONFIG.ENABLE_LOGGING) {
        console.log('File uploaded:', { bucket: bucketName, key: fileName, size: validation.buffer.length });
    }

    return createResponse(200, {
        message: "File uploaded successfully",
        fileUrl: `https://${bucketName}.s3.${region || CONFIG.DEFAULT_REGION}.amazonaws.com/${fileName}`,
        fileName: fileName,
        bucketName: bucketName,
        fileSize: validation.buffer.length,
        etag: result.ETag,
        versionId: result.VersionId,
        uploadTimestamp: new Date().toISOString()
    });
}

// 2. Create Bucket Handler
async function handleCreateBucket(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, region, versioning, publicAccess } = data;

    if (!bucketName) {
        throw new ValidationError("Missing required field: bucketName");
    }

    // Validate bucket name format (AWS requirements)
    if (!bucketName.match(/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/)) {
        throw new ValidationError("Invalid bucket name format. Must be lowercase letters, numbers, periods, and hyphens.");
    }

    if (bucketName.length < 3 || bucketName.length > 63) {
        throw new ValidationError("Bucket name must be between 3 and 63 characters");
    }

    const s3Client = createS3Client(credentials, region);
    
    const createParams = { Bucket: bucketName };
    const targetRegion = region || CONFIG.DEFAULT_REGION;
    
    // Add region configuration for non us-east-1
    if (targetRegion !== 'us-east-1') {
        createParams.CreateBucketConfiguration = { LocationConstraint: targetRegion };
    }

    await s3Client.send(new CreateBucketCommand(createParams));

    return createResponse(200, {
        message: "Bucket created successfully",
        bucketName: bucketName,
        region: targetRegion,
        versioning: versioning || false,
        publicAccess: publicAccess || false,
        createdAt: new Date().toISOString()
    });
}

// 3. Create Folder Handler
async function handleCreateFolder(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, folderName, region } = data;

    if (!bucketName || !folderName) {
        throw new ValidationError("Missing required fields: bucketName, folderName");
    }

    validateBucketAccess(bucketName);

    const s3Client = createS3Client(credentials, region);
    const folderKey = folderName.endsWith('/') ? folderName : `${folderName}/`;

    await s3Client.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: folderKey,
        Body: '',
        ContentType: 'application/x-directory',
        ServerSideEncryption: CONFIG.ENCRYPTION_TYPE
    }));

    return createResponse(200, {
        message: "Folder created successfully",
        folderName: folderKey,
        bucketName: bucketName,
        createdAt: new Date().toISOString()
    });
}

// 4. Create Object Handler
async function handleCreateObject(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, objectKey, content, contentType, region, encoding } = data;

    if (!bucketName || !objectKey) {
        throw new ValidationError("Missing required fields: bucketName, objectKey");
    }

    validateBucketAccess(bucketName);

    const s3Client = createS3Client(credentials, region);
    
    let objectBuffer;
    if (encoding === 'base64') {
        objectBuffer = Buffer.from(content || '', 'base64');
    } else {
        objectBuffer = Buffer.from(content || '', 'utf8');
    }

    const result = await s3Client.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: objectKey,
        Body: objectBuffer,
        ContentType: contentType || 'text/plain',
        ServerSideEncryption: CONFIG.ENCRYPTION_TYPE
    }));

    return createResponse(200, {
        message: "Object created successfully",
        objectKey: objectKey,
        bucketName: bucketName,
        contentType: contentType || 'text/plain',
        size: objectBuffer.length,
        etag: result.ETag,
        createdAt: new Date().toISOString()
    });
}

// 5. Delete File Handler
async function handleDeleteFile(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, fileName, region } = data;

    if (!bucketName || !fileName) {
        throw new ValidationError("Missing required fields: bucketName, fileName");
    }

    validateBucketAccess(bucketName);

    const s3Client = createS3Client(credentials, region);

    const result = await s3Client.send(new DeleteObjectCommand({
        Bucket: bucketName,
        Key: fileName
    }));

    return createResponse(200, {
        message: "File deleted successfully",
        deletedItem: fileName,
        bucketName: bucketName,
        versionId: result.VersionId,
        deletedAt: new Date().toISOString()
    });
}

// 6. Delete Folder Handler
async function handleDeleteFolder(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, folderName, force, region } = data;

    if (!bucketName || !folderName) {
        throw new ValidationError("Missing required fields: bucketName, folderName");
    }

    validateBucketAccess(bucketName);

    const s3Client = createS3Client(credentials, region);
    const folderPrefix = folderName.endsWith('/') ? folderName : `${folderName}/`;

    // List all objects in folder
    const listResponse = await s3Client.send(new ListObjectsV2Command({
        Bucket: bucketName,
        Prefix: folderPrefix,
        MaxKeys: 1000
    }));

    const objects = listResponse.Contents || [];

    if (objects.length === 0) {
        throw new ValidationError("Folder not found or is already empty");
    }

    // Check if folder has contents beyond just the folder marker
    const hasFiles = objects.some(obj => obj.Key !== folderPrefix);
    if (hasFiles && !force) {
        throw new ValidationError(`Folder contains ${objects.length} object(s). Set force=true to delete folder and all contents`);
    }

    // Delete all objects in batches
    const deleteResults = [];
    for (let i = 0; i < objects.length; i += 1000) {
        const batch = objects.slice(i, i + 1000);
        const deleteResult = await s3Client.send(new DeleteObjectsCommand({
            Bucket: bucketName,
            Delete: {
                Objects: batch.map(obj => ({ Key: obj.Key })),
                Quiet: false
            }
        }));
        deleteResults.push(deleteResult);
    }

    const totalDeleted = deleteResults.reduce((sum, result) => 
        sum + (result.Deleted?.length || 0), 0);

    return createResponse(200, {
        message: "Folder deleted successfully",
        deletedItem: folderPrefix,
        bucketName: bucketName,
        deletedObjects: totalDeleted,
        deletedAt: new Date().toISOString()
    });
}

// 7. Get Object Handler
async function handleGetObject(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, objectKey, downloadUrl, region, encoding } = data;

    if (!bucketName || !objectKey) {
        throw new ValidationError("Missing required fields: bucketName, objectKey");
    }

    validateBucketAccess(bucketName);

    const s3Client = createS3Client(credentials, region);

    if (downloadUrl) {
        // Generate presigned URL
        const command = new GetObjectCommand({
            Bucket: bucketName,
            Key: objectKey
        });

        const signedUrl = await getSignedUrl(s3Client, command, { 
            expiresIn: CONFIG.PRESIGNED_URL_EXPIRY 
        });

        return createResponse(200, {
            message: "Download URL generated successfully",
            objectKey: objectKey,
            downloadUrl: signedUrl,
            expiresIn: CONFIG.PRESIGNED_URL_EXPIRY
        });
    } else {
        // Get object content
        const getResponse = await s3Client.send(new GetObjectCommand({
            Bucket: bucketName,
            Key: objectKey
        }));

        const content = await streamToBuffer(getResponse.Body);
        
        // Encode based on requested format
        const encodedContent = encoding === 'utf8' 
            ? content.toString('utf8')
            : content.toString('base64');

        return createResponse(200, {
            message: "Object retrieved successfully",
            objectKey: objectKey,
            content: encodedContent,
            encoding: encoding || 'base64',
            contentType: getResponse.ContentType,
            size: content.length,
            lastModified: getResponse.LastModified,
            etag: getResponse.ETag
        });
    }
}

// 8. List Buckets Handler
async function handleListBuckets(event, credentials) {
    const data = parseRequestBody(event);
    const { region } = data;

    const s3Client = createS3Client(credentials, region);
    const response = await s3Client.send(new ListBucketsCommand({}));

    let buckets = response.Buckets?.map(bucket => ({
        name: bucket.Name,
        creationDate: bucket.CreationDate
    })) || [];

    // Apply bucket filtering if configured
    if (CONFIG.ALLOWED_BUCKETS.length > 0) {
        buckets = buckets.filter(bucket => CONFIG.ALLOWED_BUCKETS.includes(bucket.name));
    }

    return createResponse(200, {
        message: "Buckets listed successfully",
        buckets: buckets,
        count: buckets.length
    });
}

// 9. List Files Handler
async function handleListFiles(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, prefix, maxKeys, continuationToken, region } = data;

    if (!bucketName) {
        throw new ValidationError("Missing required field: bucketName");
    }

    validateBucketAccess(bucketName);

    const s3Client = createS3Client(credentials, region);
    
    const listParams = {
        Bucket: bucketName,
        Prefix: prefix || '',
        MaxKeys: Math.min(maxKeys || 1000, 1000)
    };

    if (continuationToken) {
        listParams.ContinuationToken = continuationToken;
    }

    const response = await s3Client.send(new ListObjectsV2Command(listParams));

    const files = response.Contents?.map(object => ({
        key: object.Key,
        name: object.Key.split('/').pop(),
        lastModified: object.LastModified,
        size: object.Size,
        storageClass: object.StorageClass,
        etag: object.ETag
    })) || [];

    return createResponse(200, {
        message: "Files listed successfully",
        files: files,
        bucketName: bucketName,
        count: files.length,
        isTruncated: response.IsTruncated,
        nextContinuationToken: response.NextContinuationToken
    });
}

// 10. List Folder Contents Handler
async function handleListFolderContents(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, folderPath, region, includeSubfolders } = data;

    if (!bucketName) {
        throw new ValidationError("Missing required field: bucketName");
    }

    validateBucketAccess(bucketName);

    const s3Client = createS3Client(credentials, region);
    const prefix = folderPath && !folderPath.endsWith('/') ? `${folderPath}/` : (folderPath || '');

    const listParams = {
        Bucket: bucketName,
        Prefix: prefix,
        MaxKeys: 1000
    };

    // Use delimiter to separate folders unless including subfolders
    if (!includeSubfolders) {
        listParams.Delimiter = '/';
    }

    const response = await s3Client.send(new ListObjectsV2Command(listParams));

    const folders = response.CommonPrefixes?.map(prefixObj => ({
        name: prefixObj.Prefix.replace(prefix, '').replace('/', ''),
        fullPath: prefixObj.Prefix,
        type: 'folder'
    })) || [];

    const files = response.Contents?.filter(object => object.Key !== prefix).map(object => ({
        key: object.Key,
        name: object.Key.replace(prefix, ''),
        lastModified: object.LastModified,
        size: object.Size,
        storageClass: object.StorageClass,
        type: 'file'
    })) || [];

    return createResponse(200, {
        message: "Folder contents listed successfully",
        path: prefix || '/',
        folders: folders,
        files: files,
        totalItems: folders.length + files.length
    });
}

// 11. Batch Delete Handler (New)
async function handleBatchDelete(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, objects, region } = data;

    if (!bucketName || !objects || !Array.isArray(objects)) {
        throw new ValidationError("Missing required fields: bucketName, objects (array)");
    }

    if (objects.length === 0) {
        throw new ValidationError("Objects array cannot be empty");
    }

    if (objects.length > 1000) {
        throw new ValidationError("Maximum 1000 objects can be deleted at once");
    }

    validateBucketAccess(bucketName);

    const s3Client = createS3Client(credentials, region);

    const deleteResult = await s3Client.send(new DeleteObjectsCommand({
        Bucket: bucketName,
        Delete: {
            Objects: objects.map(key => ({ Key: key })),
            Quiet: false
        }
    }));

    return createResponse(200, {
        message: "Batch delete completed",
        bucketName: bucketName,
        deleted: deleteResult.Deleted?.map(d => d.Key) || [],
        errors: deleteResult.Errors?.map(e => ({
            key: e.Key,
            code: e.Code,
            message: e.Message
        })) || [],
        deletedCount: deleteResult.Deleted?.length || 0,
        errorCount: deleteResult.Errors?.length || 0
    });
}

// 12. Copy Object Handler (New)
async function handleCopyObject(event, credentials) {
    const data = parseRequestBody(event);
    const { sourceBucket, sourceKey, destinationBucket, destinationKey, region } = data;

    if (!sourceBucket || !sourceKey || !destinationBucket || !destinationKey) {
        throw new ValidationError("Missing required fields: sourceBucket, sourceKey, destinationBucket, destinationKey");
    }

    validateBucketAccess(sourceBucket);
    validateBucketAccess(destinationBucket);

    const s3Client = createS3Client(credentials, region);

    const copySource = `${sourceBucket}/${sourceKey}`;
    
    const result = await s3Client.send(new CopyObjectCommand({
        Bucket: destinationBucket,
        Key: destinationKey,
        CopySource: copySource,
        ServerSideEncryption: CONFIG.ENCRYPTION_TYPE
    }));

    return createResponse(200, {
        message: "Object copied successfully",
        source: `${sourceBucket}/${sourceKey}`,
        destination: `${destinationBucket}/${destinationKey}`,
        etag: result.CopyObjectResult?.ETag,
        lastModified: result.CopyObjectResult?.LastModified
    });
}

// 13. Get Presigned URL Handler (New)
async function handleGetPresignedUrl(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, objectKey, operation, expiresIn, region } = data;

    if (!bucketName || !objectKey || !operation) {
        throw new ValidationError("Missing required fields: bucketName, objectKey, operation");
    }

    if (!['upload', 'download'].includes(operation)) {
        throw new ValidationError("Operation must be 'upload' or 'download'");
    }

    validateBucketAccess(bucketName);

    const s3Client = createS3Client(credentials, region);
    
    const command = operation === 'upload'
        ? new PutObjectCommand({ Bucket: bucketName, Key: objectKey })
        : new GetObjectCommand({ Bucket: bucketName, Key: objectKey });

    const expiry = Math.min(expiresIn || CONFIG.PRESIGNED_URL_EXPIRY, 604800); // Max 7 days
    const signedUrl = await getSignedUrl(s3Client, command, { expiresIn: expiry });

    return createResponse(200, {
        message: `${operation} URL generated successfully`,
        url: signedUrl,
        operation: operation,
        objectKey: objectKey,
        bucketName: bucketName,
        expiresIn: expiry,
        expiresAt: new Date(Date.now() + expiry * 1000).toISOString()
    });
}

// 14. Check Object Exists Handler (New)
async function handleCheckObjectExists(event, credentials) {
    const data = parseRequestBody(event);
    const { bucketName, objectKey, region } = data;

    if (!bucketName || !objectKey) {
        throw new ValidationError("Missing required fields: bucketName, objectKey");
    }

    validateBucketAccess(bucketName);

    const s3Client = createS3Client(credentials, region);

    try {
        const response = await s3Client.send(new HeadObjectCommand({
            Bucket: bucketName,
            Key: objectKey
        }));

        return createResponse(200, {
            exists: true,
            objectKey: objectKey,
            bucketName: bucketName,
            size: response.ContentLength,
            lastModified: response.LastModified,
            contentType: response.ContentType,
            etag: response.ETag
        });
    } catch (error) {
        if (error.name === 'NotFound' || error.$metadata?.httpStatusCode === 404) {
            return createResponse(200, {
                exists: false,
                objectKey: objectKey,
                bucketName: bucketName
            });
        } else {
            throw error;
        }
    }
}

// Helper Functions

// Convert stream to buffer
async function streamToBuffer(stream) {
    const chunks = [];
    for await (const chunk of stream) {
        chunks.push(chunk);
    }
    return Buffer.concat(chunks);
}

// Create standardized response
function createResponse(statusCode, body) {
    return {
        statusCode: statusCode,
        headers: corsHeaders,
        body: JSON.stringify(body)
    };
}

// Error handling
function handleError(error, requestId) {
    let statusCode = 500;
    let errorMessage = "Internal server error";
    let errorCode = "INTERNAL_ERROR";

    // Custom error types
    if (error instanceof AuthenticationError) {
        statusCode = 401;
        errorMessage = error.message;
        errorCode = "AUTHENTICATION_ERROR";
    } else if (error instanceof ValidationError) {
        statusCode = 400;
        errorMessage = error.message;
        errorCode = "VALIDATION_ERROR";
    } else if (error instanceof RateLimitError) {
        statusCode = 429;
        errorMessage = error.message;
        errorCode = "RATE_LIMIT_ERROR";
    } else {
        // AWS SDK errors
        switch (error.name || error.Code) {
            case 'InvalidAccessKeyId':
            case 'SignatureDoesNotMatch':
                statusCode = 401;
                errorMessage = "Invalid AWS credentials";
                errorCode = "INVALID_CREDENTIALS";
                break;
            case 'AccessDenied':
            case 'Forbidden':
                statusCode = 403;
                errorMessage = "Access denied - insufficient permissions";
                errorCode = "ACCESS_DENIED";
                break;
            case 'NoSuchBucket':
                statusCode = 404;
                errorMessage = "Bucket not found";
                errorCode = "BUCKET_NOT_FOUND";
                break;
            case 'NoSuchKey':
            case 'NotFound':
                statusCode = 404;
                errorMessage = "Object not found";
                errorCode = "OBJECT_NOT_FOUND";
                break;
            case 'BucketAlreadyExists':
            case 'BucketAlreadyOwnedByYou':
                statusCode = 409;
                errorMessage = "Bucket already exists";
                errorCode = "BUCKET_EXISTS";
                break;
            case 'EntityTooLarge':
            case 'RequestEntityTooLarge':
                statusCode = 413;
                errorMessage = "File size exceeds maximum allowed";
                errorCode = "FILE_TOO_LARGE";
                break;
            case 'SlowDown':
            case 'RequestLimitExceeded':
                statusCode = 429;
                errorMessage = "Too many requests - please slow down";
                errorCode = "RATE_LIMITED";
                break;
            case 'ServiceUnavailable':
                statusCode = 503;
                errorMessage = "S3 service temporarily unavailable";
                errorCode = "SERVICE_UNAVAILABLE";
                break;
            default:
                // Log unexpected errors for debugging
                console.error("Unexpected error:", error);
                errorMessage = error.message || errorMessage;
                break;
        }
    }

    return {
        statusCode: statusCode,
        headers: corsHeaders,
        body: JSON.stringify({
            error: errorMessage,
            code: errorCode,
            requestId: requestId,
            timestamp: new Date().toISOString()
        })
    };
}

// Custom error classes
class AuthenticationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'AuthenticationError';
    }
}

class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ValidationError';
    }
}

class RateLimitError extends Error {
    constructor(message) {
        super(message);
        this.name = 'RateLimitError';
    }
}
