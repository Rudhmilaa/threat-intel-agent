"use client";

import {useUser} from "@/components/hooks/hooks";
import {Button, Stack, TextField, Typography} from "@mui/material";
import {Copy} from "lucide-react";
import React, {useEffect} from "react";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import {toast} from "sonner";
import {generateToken} from "@/lib/utils";
import {updateToken, updateUser} from "@/lib/actions";
import {UpdatePasswordSchema} from "@/app/auth/definitions";

function Account() {
  const {user, isLoading, error, mutate} = useUser();
  const [email, setEmail] = React.useState("");
  const [pass1, setPass1] = React.useState("");
  const [pass2, setPass2] = React.useState("");
  const [passwordError, setPasswordError] = React.useState<
    string[] | undefined
  >(undefined);
  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(user.token);
      toast.success(`API Token copied to clipboard.`);
    } catch (err) {
      toast.error("Failed to copy API Token to clipboard.");
    }
  };

  const handleUpdateAccount = () => {
    updateUser({email: email.toLowerCase()})
      .then((data) => {
        mutate();
        toast.success("Account updated successfully.");
      })
      .catch((err) => {
        toast.error("Failed to update account.");
      });
  };
  const handleUpdateToken = () => {
    const token = generateToken();

    // Update the user token
    updateToken({token: token})
      .then((user) => {
        mutate();
        toast.success("API Token updated successfully.");
      })
      .catch((err) => {
        console.error("Error updating token", err);
        toast.error("Failed to update API Token.");
      });
  };
  const handleUpdatePassword = () => {
    // Validate password
    if (pass1 !== pass2) {
      setPasswordError(["Passwords do not match."]);
      return;
    }
    // 1. Validate form fields
    const validatedPass = UpdatePasswordSchema.safeParse({
      password: pass1,
    });

    // If any form fields are invalid, return early
    if (!validatedPass.success) {
      setPasswordError(validatedPass.error.flatten().fieldErrors.password);
      return;
    }

    // 2. Prepare data for insertion into database
    const password = validatedPass.data?.password;
    setPasswordError(undefined);

    // Update the user password
    updateUser({password: password})
      .then((data) => {
        toast.success("Password updated successfully.");
      })
      .catch((err) => {
        console.error("Error updating password", err);
        toast.error("Failed to update password.");
      });
  };

  // Initialize email state when user data is available
  useEffect(() => {
    if (user?.email) {
      setEmail(user.email);
    }
  }, [user]);

  if (isLoading) {
    return <div>Loading...</div>;
  }
  if (error) {
    return <div>Error loading user</div>;
  }
  return (
    <div>
      <Typography variant="h5" style={{marginBottom: 8}}>
        Account
      </Typography>
      <Typography variant="body2" style={{marginBottom: 16}}>
        Update your account info
      </Typography>
      <Stack spacing={4} className="w-1/2">
        <TextField disabled label="Username" value={user.username} />
        <TextField
          label="Email"
          type="email"
          value={email}
          onChange={(event) => {
            setEmail(event.target.value);
          }}
          autoComplete="email"
        />
        <Stack direction="row" spacing={2}>
          <TextField
            disabled
            className="w-full"
            label="API Token"
            value={user.token}
          />
          <Button variant="outlined" onClick={copyToClipboard}>
            <Copy />
          </Button>
          <Button
            variant="outlined"
            color="primary"
            onClick={handleUpdateToken}
            disabled={user?.username === "admin"}
          >
            <AutorenewIcon />
          </Button>
        </Stack>
        <Button
          variant="contained"
          color="primary"
          className="w-fit"
          onClick={handleUpdateAccount}
        >
          Update Account
        </Button>
      </Stack>
      <Typography variant="h5" style={{marginBottom: 8, marginTop: 54}}>
        Security
      </Typography>
      <Typography variant="body2" style={{marginBottom: 16}}>
        Update your password
      </Typography>
      <Stack spacing={4} className="w-1/2 mt-8">
        <TextField
          label="New Password"
          value={pass1}
          type="password"
          onChange={(event) => {
            setPass1(event.target.value);
          }}
          autoComplete="new-password"
          error={!!passwordError}
          aria-invalid={!!passwordError}
          aria-describedby={passwordError ? "password-error" : undefined}
        />
        <TextField
          label="Confirm Password"
          value={pass2}
          type="password"
          onChange={(event) => {
            setPass2(event.target.value);
          }}
          autoComplete="new-password"
          error={!!passwordError}
          aria-invalid={!!passwordError}
          aria-describedby={passwordError ? "password-error" : undefined}
        />

        {passwordError && (
          <Stack
            id="password-error"
            role="alert"
            aria-live="polite"
            style={{marginLeft: 8}}
          >
            <p className="text-sm text-red-500">Password must:</p>
            {passwordError.map((error, i) => (
              <p key={i} className="text-sm text-red-500 ml-2">
                {error}
              </p>
            ))}
          </Stack>
        )}

        <Button
          variant="contained"
          color="primary"
          className="w-fit"
          onClick={handleUpdatePassword}
        >
          Update Password
        </Button>
      </Stack>
    </div>
  );
}

export default Account;
