package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"jwk-jwt-auth/internal/manager"
	"jwk-jwt-auth/model"
	"jwk-jwt-auth/service"
	"os"
	"strconv"
	"strings"
)

var menuCmd = &cobra.Command{
	Use:   "menu",
	Short: "Interactive menu for JWT operations",
	Run:   runMenu,
}

func init() {
	rootCmd.AddCommand(menuCmd)
}

func runMenu(cmd *cobra.Command, args []string) {
	var jwkManager = manager.NewJwkManager()
	if err := jwkManager.InitializeJwkSet(2); err != nil {
		fmt.Printf("Error initializing JWK set: %v\n", err)
		return
	}

	var jwtManager = manager.NewJwtManager(jwkManager)
	var authService = service.NewAuthService(jwtManager, jwkManager)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\nJWT Authentication Menu:")
		fmt.Println("1. Generate Token")
		fmt.Println("2. Get JWKS")
		fmt.Println("3. Verify JWT")
		fmt.Println("4. Exit")
		fmt.Print("\nSelect an option: ")

		choice, errReadingInput := reader.ReadString('\n')
		if errReadingInput != nil {
			fmt.Printf("Failed to read input: %v\n", errReadingInput)
			continue
		}
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			generateTokenInteractive(authService, reader)
		case "2":
			getJWKSInteractive(authService)
		case "3":
			verifyTokenInteractive(authService, reader)
		case "4":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Println("Invalid option, please try again")
		}
	}
}

func generateTokenInteractive(authService service.IAuthService, reader *bufio.Reader) {
	fmt.Print("Enter user ID: ")
	userId, errReadingUserIdInput := reader.ReadString('\n')
	if errReadingUserIdInput != nil {
		fmt.Printf("Failed to read input: %v\n", errReadingUserIdInput)
		return
	}
	userIdInInt, errParsingString := strconv.Atoi(strings.TrimSpace(userId))
	if errParsingString != nil {
		fmt.Printf("Invalid user ID: %v\n", errParsingString)
		return
	}

	fmt.Print("Enter username: ")
	username, errReadingUserUserNameInput := reader.ReadString('\n')
	if errReadingUserUserNameInput != nil {
		fmt.Printf("Failed to read input: %v\n", errReadingUserUserNameInput)
		return
	}

	username = strings.TrimSpace(username)

	user := &model.User{
		Id:       userIdInInt,
		Username: username,
	}

	token, err := authService.GenerateJwt(user)
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	fmt.Printf("\nGenerated Token: %s\n", token)
}

func getJWKSInteractive(authService service.IAuthService) {
	jwks, err := authService.GetPublicKeys()
	if err != nil {
		fmt.Printf("Error getting JWKS: %v\n", err)
		return
	}

	bytes, err := json.Marshal(jwks)
	if err != nil {
		fmt.Printf("Error getting marshalling data: %v\n", err)
		return
	}

	fmt.Printf("\nPublic JWKS: %+v\n", string(bytes))
}

func verifyTokenInteractive(authService service.IAuthService, reader *bufio.Reader) {
	fmt.Print("Enter JWT token: ")
	token, _ := reader.ReadString('\n')
	token = strings.TrimSpace(token)

	claims, err := authService.VerifyToken(token)
	if err != nil {
		fmt.Printf("Error verifying token: %v\n", err)
		return
	}

	fmt.Printf("\nToken Claims: %+v\n", claims)
}
