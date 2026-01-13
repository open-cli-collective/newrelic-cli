package users

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/api"
	"github.com/piekstra/newrelic-cli/internal/cmd/root"
	"github.com/piekstra/newrelic-cli/internal/view"
)

// Register adds the users commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	usersCmd := &cobra.Command{
		Use:     "users",
		Aliases: []string{"user"},
		Short:   "Manage New Relic users",
	}

	usersCmd.AddCommand(newListCmd(opts))
	usersCmd.AddCommand(newGetCmd(opts))

	rootCmd.AddCommand(usersCmd)
}

func newListCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all users",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(opts)
		},
	}
}

func runList(opts *root.Options) error {
	client, err := api.New()
	if err != nil {
		return err
	}

	users, err := client.ListUsers()
	if err != nil {
		return err
	}

	v := opts.View()

	if len(users) == 0 {
		v.Println("No users found")
		return nil
	}

	headers := []string{"ID", "NAME", "EMAIL", "TYPE", "DOMAIN"}
	rows := make([][]string, len(users))
	for i, u := range users {
		rows[i] = []string{
			u.ID,
			view.Truncate(u.Name, 25),
			view.Truncate(u.Email, 30),
			u.Type,
			view.Truncate(u.AuthenticationDomain, 20),
		}
	}

	return v.Render(headers, rows, users)
}

func newGetCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <user-id>",
		Short: "Get details for a specific user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(opts, args[0])
		},
	}
}

func runGet(opts *root.Options, userID string) error {
	client, err := api.New()
	if err != nil {
		return err
	}

	user, err := client.GetUser(userID)
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "json":
		return v.JSON(user)
	case "plain":
		return v.Plain([][]string{
			{user.ID, user.Name, user.Email, user.Type},
		})
	default:
		v.Print("ID:                    %s\n", user.ID)
		v.Print("Name:                  %s\n", user.Name)
		v.Print("Email:                 %s\n", user.Email)
		v.Print("Type:                  %s\n", user.Type)
		v.Print("Authentication Domain: %s\n", user.AuthenticationDomain)
		if len(user.Groups) > 0 {
			v.Print("Groups:                %s\n", strings.Join(user.Groups, ", "))
		}
		return nil
	}
}
