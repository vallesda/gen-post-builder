package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	pb "./proto"
)

const (
	grpcPort       = ":50051"
	restPort       = ":8080"
	contentAgentAddr = "localhost:50052"
	rateLimit      = 100 // Max requests per minute
)

var (
	rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})
	secretKey = []byte("supersecretkey")
)

type AuthClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func authenticateJWT(tokenString string) (*AuthClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AuthClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*AuthClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

func rateLimitMiddleware(username string) bool {
	ctx := context.Background()
	key := fmt.Sprintf("ratelimit:%s", username)
	count, _ := rdb.Incr(ctx, key).Result()
	if count == 1 {
		rdb.Expire(ctx, key, time.Minute)
	}
	return count <= rateLimit
}

func generateContent(requestType string, prompt string) (string, error) {
	conn, err := grpc.Dial(contentAgentAddr, grpc.WithInsecure())
	if err != nil {
		return "", fmt.Errorf("failed to connect to content agent: %v", err)
	}
	defer conn.Close()
	
	client := pb.NewContentAgentClient(conn)
	resp, err := client.GenerateContent(context.Background(), &pb.ContentRequest{Type: requestType, Prompt: prompt})
	if err != nil {
		return "", fmt.Errorf("failed to generate content: %v", err)
	}
	return resp.Content, nil
}

func grpcServer() {
	listener, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	reflection.Register(grpcServer)
	log.Printf("gRPC server running on %s", grpcPort)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func restServer() {
	r := gin.Default()

	r.Use(func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			c.Abort()
			return
		}
		claims, err := authenticateJWT(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}
		if !rateLimitMiddleware(claims.Username) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			c.Abort()
			return
		}
		c.Set("username", claims.Username)
		c.Next()
	})

	r.POST("/generate_content", func(c *gin.Context) {
		var request struct {
			Type   string `json:"type"`
			Prompt string `json:"prompt"`
		}
		if err := c.BindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		content, err := generateContent(request.Type, request.Prompt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"content": content})
	})

	r.Run(restPort)
}

func main() {
	go grpcServer()
	restServer()
}
