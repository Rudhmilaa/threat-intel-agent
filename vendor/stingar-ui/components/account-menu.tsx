"use client";

import * as React from "react";
import Avatar from "@mui/material/Avatar";
import Menu from "@mui/material/Menu";
import MenuItem from "@mui/material/MenuItem";
import ListItemIcon from "@mui/material/ListItemIcon";
import Divider from "@mui/material/Divider";
import AccountIcon from "@mui/icons-material/AccountCircleOutlined";
import Settings from "@mui/icons-material/Settings";
import Logout from "@mui/icons-material/Logout";
import Button from "@mui/material/Button";
import KeyboardArrowDown from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowUp from "@mui/icons-material/KeyboardArrowUp";
import { logout } from "@/app/auth/auth";
import { redirect } from "next/navigation";
import { useUser } from "./hooks/hooks";

export default function AccountMenu() {
  const { user } = useUser();
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  const Arrow = open ? KeyboardArrowDown : KeyboardArrowUp;
  return (
    <React.Fragment>
      <Button
        onClick={handleClick}
        size="small"
        sx={{
          ml: 2,
          backgroundColor: "transparent",
          boxShadow: "none",
          ":hover": {
            backgroundColor: "transparent",
            boxShadow: "none",
          },
        }}
        aria-controls={open ? "account-menu" : undefined}
        aria-haspopup="true"
        aria-expanded={open ? "true" : undefined}
        endIcon={<Arrow style={{ color: "white", height: 16, width: 16 }} />}
      >
        <Avatar>{user?.username?.charAt(0).toUpperCase() || "A"}</Avatar>
      </Button>
      <Menu
        anchorEl={anchorEl}
        id="account-menu"
        open={open}
        onClose={handleClose}
        onClick={handleClose}
        slotProps={{
          paper: {
            elevation: 0,
          },
        }}
      >
        <div className="p-4 flex flex-col">
          <span className="">{user?.username || "Username"}</span>
          <span className="text-gray-600 text-sm">
            {user?.email || "Email"}
          </span>
        </div>
        <Divider />
        <MenuItem
          onClick={() => {
            handleClose();
            redirect("/account");
          }}
        >
          <ListItemIcon>
            <AccountIcon fontSize="small" />
          </ListItemIcon>
          Account
        </MenuItem>
        <MenuItem
          onClick={async () => {
            await logout();
          }}
        >
          <ListItemIcon>
            <Logout fontSize="small" />
          </ListItemIcon>
          Sign out
        </MenuItem>
      </Menu>
    </React.Fragment>
  );
}
