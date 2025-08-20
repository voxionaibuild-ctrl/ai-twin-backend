import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertUserSchema, loginSchema, insertMessageSchema } from "@shared/schema";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Database from "@replit/database";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const GROQ_API_KEY = process.env.GROQ_API_KEY || "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";

// Initialize Replit DB
const db = new Database();

interface AuthRequest extends Request {
  user?: { id: string; email: string; username: string };
}

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

// Helper functions for chat memory
async function getChatHistory(userId: string): Promise<ChatMessage[]> {
  try {
    const historyKey = `chat_history_${userId}`;
    const result = await db.get(historyKey);
    
    // If no result, start with empty array
    if (!result) {
      return [];
    }
    
    // Handle Replit DB response format with ok/value structure
    if (typeof result === 'object' && result !== null && 'ok' in result) {
      if (result.ok && 'value' in result && Array.isArray(result.value)) {
        return result.value;
      }
      // If ok is false, it means the key doesn't exist yet
      return [];
    }
    
    // If it's already an array, return it
    if (Array.isArray(result)) {
      return result;
    }
    
    // If it's an object with numeric keys (array-like object from Replit DB)
    if (typeof result === 'object' && result !== null) {
      // Try to convert object with numeric keys back to array
      const keys = Object.keys(result);
      if (keys.length > 0 && keys.every(key => !isNaN(Number(key)))) {
        const arrayResult: ChatMessage[] = [];
        for (let i = 0; i < keys.length; i++) {
          if (result[i]) {
            arrayResult.push(result[i]);
          }
        }
        return arrayResult;
      }
    }
    
    // For any other case, return empty array to avoid parsing errors
    return [];
  } catch (error) {
    console.error('Error getting chat history:', error);
    return [];
  }
}

async function saveChatHistory(userId: string, messages: ChatMessage[]): Promise<void> {
  try {
    // Keep only the last 15 messages to avoid DB size issues
    const trimmedMessages = messages.slice(-15);
    const historyKey = `chat_history_${userId}`;
    
    console.log(`Saving ${trimmedMessages.length} messages to DB for user ${userId}`);
    
    // Store as array directly
    await db.set(historyKey, trimmedMessages);
    
    // Verify save worked by immediately reading back
    const verification = await db.get(historyKey);
    console.log(`Verification: saved data type is ${typeof verification}, isArray: ${Array.isArray(verification)}`);
  } catch (error) {
    console.error('Error saving chat history:', error);
  }
}

async function addMessageToHistory(userId: string, role: 'user' | 'assistant', content: string): Promise<void> {
  const history = await getChatHistory(userId);
  const newMessage: ChatMessage = {
    role,
    content,
    timestamp: new Date().toISOString()
  };
  history.push(newMessage);
  await saveChatHistory(userId, history);
}

// Auth middleware
const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    const user = await storage.getUser(decoded.id);
    if (!user) {
      return res.status(401).json({ message: 'Invalid token' });
    }
    req.user = { id: user.id, email: user.email, username: user.username };
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth routes
  app.post("/api/auth/signup", async (req, res) => {
    try {
      const userData = insertUserSchema.parse(req.body);
      
      // Check if user already exists
      const existingUser = await storage.getUserByEmail(userData.email);
      if (existingUser) {
        return res.status(400).json({ message: 'User already exists with this email' });
      }

      const existingUsername = await storage.getUserByUsername(userData.username);
      if (existingUsername) {
        return res.status(400).json({ message: 'Username already taken' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(userData.password, 10);
      
      // Create user
      const user = await storage.createUser({
        ...userData,
        password: hashedPassword,
      });

      // Generate JWT
      const token = jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        token,
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
        },
      });
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    try {
      const loginData = loginSchema.parse(req.body);
      
      // Find user
      const user = await storage.getUserByEmail(loginData.email);
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Verify password
      const validPassword = await bcrypt.compare(loginData.password, user.password);
      if (!validPassword) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Generate JWT
      const token = jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        token,
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
        },
      });
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  });

  // Protected routes
  app.get("/api/auth/me", authenticateToken, (req: AuthRequest, res: Response) => {
    res.json({ user: req.user });
  });

  // Test route for memory debugging
  app.get("/api/debug/memory", authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
      const historyKey = `chat_history_${req.user!.id}`;
      const rawResult = await db.get(historyKey);
      const chatHistory = await getChatHistory(req.user!.id);
      
      res.json({
        userId: req.user!.id,
        historyKey,
        rawResult,
        rawResultType: typeof rawResult,
        rawResultIsArray: Array.isArray(rawResult),
        rawResultKeys: rawResult ? Object.keys(rawResult) : null,
        historyCount: chatHistory.length,
        history: chatHistory
      });
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  });

  app.get("/api/messages", authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
      // Get chat history from Replit DB
      const chatHistory = await getChatHistory(req.user!.id);
      
      // Convert to the format expected by the frontend
      const messages = chatHistory.map((msg, index) => ({
        id: `${req.user!.id}_${index}`,
        userId: req.user!.id,
        role: msg.role === 'assistant' ? 'ai' : msg.role,
        content: msg.content,
        createdAt: new Date(msg.timestamp)
      }));
      
      res.json(messages);
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  });

  app.post("/api/chat", authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
      const { content } = req.body;
      
      if (!content || typeof content !== 'string') {
        return res.status(400).json({ message: 'Message content is required' });
      }

      // Get chat history for context
      const chatHistory = await getChatHistory(req.user!.id);
      console.log(`Retrieved ${chatHistory.length} messages from chat history for user ${req.user!.id}`);
      
      // Build messages array with history for AI context
      const messages = [
        {
          role: 'system' as const,
          content: 'You are a helpful AI twin companion. You are friendly, knowledgeable, and engaging. Keep responses conversational and helpful. You can reference previous parts of our conversation naturally.',
        },
        // Include recent chat history for context
        ...chatHistory.slice(-10).map(msg => ({
          role: msg.role === 'assistant' ? 'assistant' as const : 'user' as const,
          content: msg.content,
        })),
        // Add the new user message
        {
          role: 'user' as const,
          content,
        },
      ];
      
      console.log(`Sending ${messages.length} messages to Groq API including ${chatHistory.length} history messages`);

      // Save user message to memory
      await addMessageToHistory(req.user!.id, 'user', content);

      // Call Groq API with full context
      const groqResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${GROQ_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'llama3-8b-8192',
          messages,
          max_tokens: 1000,
          temperature: 0.7,
        }),
      });

      if (!groqResponse.ok) {
        const errorText = await groqResponse.text();
        console.error('Groq API error:', errorText);
        throw new Error(`Failed to get AI response: ${groqResponse.status}`);
      }

      const groqData = await groqResponse.json();
      const aiContent = groqData.choices[0]?.message?.content || 'Sorry, I could not generate a response.';

      // Save AI response to memory
      await addMessageToHistory(req.user!.id, 'assistant', aiContent);

      // Also save to local storage for compatibility
      const userMessage = await storage.createMessage({
        userId: req.user!.id,
        role: 'user',
        content,
      });

      const aiMessage = await storage.createMessage({
        userId: req.user!.id,
        role: 'ai',
        content: aiContent,
      });

      res.json({
        userMessage,
        aiMessage,
      });
    } catch (error: any) {
      console.error('Chat error:', error);
      res.status(500).json({ message: 'Failed to process chat message' });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
