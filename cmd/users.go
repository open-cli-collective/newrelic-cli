package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piekstra/newrelic-cli/internal/client"
	"github.com/spf13/cobra"
)

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Manage New Relic users",
}

var listUsersCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		users, err := c.ListUsers()
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(users, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(users) == 0 {
			fmt.Println("No users found")
			return nil
		}

		fmt.Printf("%-15s %-25s %-35s %s\n", "ID", "NAME", "EMAIL", "TYPE")
		fmt.Println(strings.Repeat("-", 90))
		for _, u := range users {
			fmt.Printf("%-15s %-25s %-35s %s\n",
				u.ID,
				truncate(u.Name, 25),
				truncate(u.Email, 35),
				u.Type,
			)
		}

		return nil
	},
}

var getUserCmd = &cobra.Command{
	Use:   "get <user-id>",
	Short: "Get details for a specific user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		user, err := c.GetUser(args[0])
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(user, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("ID:                    %s\n", user.ID)
		fmt.Printf("Name:                  %s\n", user.Name)
		fmt.Printf("Email:                 %s\n", user.Email)
		fmt.Printf("Type:                  %s\n", user.Type)
		fmt.Printf("Authentication Domain: %s\n", user.AuthenticationDomain)
		if len(user.Groups) > 0 {
			fmt.Printf("Groups:                %s\n", strings.Join(user.Groups, ", "))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(usersCmd)
	usersCmd.AddCommand(listUsersCmd)
	usersCmd.AddCommand(getUserCmd)
}
