import type { ThemeOptions } from "@mui/material/styles";
import {
	BODY_FONT_FAMILY,
	BUTTON_LG_HEIGHT,
	BUTTON_MD_HEIGHT,
	BUTTON_SM_HEIGHT,
	BUTTON_XL_HEIGHT,
} from "./constants";
import tw from "./tailwindColors";

// biome-ignore lint/suspicious/noExplicitAny: needed for MUI overrides
type MuiStyle = any;

export const components = {
	MuiCssBaseline: {
		styleOverrides: (theme) => `
		body: {
				backgroundColor: theme.palette.background.default,
				fontFamily: BODY_FONT_FAMILY,
				fontSize: 14,
			}
		input:-webkit-autofill,
      	input:-webkit-autofill:hover,
		input:-webkit-autofill:focus,
		input:-webkit-autofill:active  {
        -webkit-box-shadow: 0 0 0 100px ${theme.palette.background.default} inset !important;

		fieldset {
			border: unset;
			padding: 0;
			margin: 0;
			width: 100%;
		}
      }
		`
	},
	MuiAvatar: {
		styleOverrides: {
			root: {
				width: 32,
				height: 32,
				fontSize: 18,

				"& .MuiSvgIcon-root": {
					width: "50%",
				},
			},
			colorDefault: ({ theme }) => ({
				backgroundColor: theme.palette.primary.dark,
				//color: theme.palette.text.primary,
			}),
		},
	},
	// Button styles are based on
	// https://tailwindui.com/components/application-ui/elements/buttons
	MuiButtonBase: {
		defaultProps: {
			disableRipple: true,
		},
	},
	MuiButton: {
		defaultProps: {
			variant: "contained",
			color: "primary",
		},
		styleOverrides: {
			root: ({ theme }) => ({
				textTransform: "none",
				letterSpacing: "normal",
				fontWeight: 500,
				height: BUTTON_MD_HEIGHT,
				padding: "8px 16px",
				borderRadius: "6px",
				fontSize: 14,

				whiteSpace: "nowrap",
				":focus-visible": {
					outline: `2px solid ${theme.palette.primary.main}`,
				},

				"& .MuiLoadingButton-loadingIndicator": {
					width: 14,
					height: 14,
				},

				"& .MuiLoadingButton-loadingIndicator .MuiCircularProgress-root": {
					width: "inherit !important",
					height: "inherit !important",
				},
			}),
			sizeSmall: {
				height: BUTTON_SM_HEIGHT,
			},
			sizeLarge: {
				height: BUTTON_LG_HEIGHT,
			},
			["sizeXlarge" as MuiStyle]: {
				height: BUTTON_XL_HEIGHT,

				// With higher size we need to increase icon spacing.
				"& .MuiButton-startIcon": {
					marginRight: 12,
				},
				"& .MuiButton-endIcon": {
					marginLeft: 12,
				},
			},

			outlined: ({ theme }) => ({
				":hover": {
					border: `1px solid ${theme.palette.primary.main}`,
				},
			}),
			["outlinedNeutral" as MuiStyle]: {
				borderColor: tw.zinc[600],

				"&.Mui-disabled": {
					borderColor: tw.zinc[700],
					color: tw.zinc[500],

					"& > .MuiLoadingButton-loadingIndicator": {
						color: tw.zinc[500],
					},
				},
			},
			["containedNeutral" as MuiStyle]: {
				backgroundColor: tw.zinc[800],

				"&:hover": {
					backgroundColor: tw.zinc[700],
				},
			},
			iconSizeMedium: {
				"& > .MuiSvgIcon-root": {
					fontSize: 14,
				},
			},
			iconSizeSmall: {
				"& > .MuiSvgIcon-root": {
					fontSize: 13,
				},
			},
		},
	},
	MuiButtonGroup: {
		styleOverrides: {
			root: ({ theme }) => ({
				">button:hover+button": {
					// The !important is unfortunate, but necessary for the border.
					borderLeftColor: `${theme.palette.secondary.main} !important`,
				},
			}),
		},
	},
	["MuiLoadingButton" as MuiStyle]: {
		defaultProps: {
			variant: "outlined",
			color: "neutral",
		},
	},
    ["MuiDataGrid" as MuiStyle]: {
		defaultProps: {
			density: "compact",
			showColumnVerticalBorder: false,
      isRowSelectable: () => false,
		},
    styleOverrides: {
      root: {
        border: "0.0px solid #f6ecd8",
		boxShadow: "0px 2px 2px rgba(0, 0, 0, 0.1)",
        borderRadius: 10,
        minHeight: "200px",
        // Remove focus border from all cells
        "& .MuiDataGrid-cell:focus, & .MuiDataGrid-cell:focus-within": {
          outline: "none",
        },
		"& .MuiDataGrid-row:hover": {
			outline: "none",
			boxShadow: "2px 2px 2px rgba(0, 0, 0, 0.2)"
		  },
        // Remove focus border from header cells
        "& .MuiDataGrid-columnHeader:focus, & .MuiDataGrid-columnHeader:focus-within": {
          outline: "none",
        },
        "& .MuiDataGrid-columnHeaders": {
          "& *": {
            backgroundColor: "#f6ecd8",
			fontWeight: "bold",
          }
      }
      },
      columnHeader: {
        textTransform: "uppercase",
        backgroundColor: "#f6ecd8",
        color: "#757475",
      },

      columnSeparator: {
        display: "none",
      },
      footerContainer: {
        borderTop: "none",
      },
      menuIcon: {
        color: "#757475",
        button: {
          color: "#757475",
        }
      },
      // Filter icon
      filterIcon: {
        color: "#757475",
      },
      // Icons container
      columnHeaderTitleContainerContent: {
        "& .MuiIconButton-root": {
          color: "#757475",
          backgroundColor: "#f6ecd8",
        }
      },
      sortIcon: {
        color: "#757475",
      },
    },
  },
	MuiPaper: {
		defaultProps: {
			elevation: 0,
		},
		styleOverrides: {
			root: ({ theme }) => ({
				border: `1px solid ${theme.palette.divider}`,
				backgroundImage: "none",
			}),
		},
	},
	MuiSkeleton: {
		styleOverrides: {
			root: ({ theme }) => ({
				backgroundColor: theme.palette.divider,
			}),
		},
	},
	MuiChip: {
		defaultProps: {
			size: "small",
		},
		styleOverrides: {
			root: {
				//backgroundColor: tw.zinc[600],
				
			},
		},
	},
	MuiMenu: {
		defaultProps: {
			anchorOrigin: {
				vertical: "bottom",
				horizontal: "right",
			},
			transformOrigin: {
				vertical: "top",
				horizontal: "right",
			},
		},
		styleOverrides: {
			paper: {
				marginTop: 8,
				borderRadius: 4,
				padding: "4px 0",
				minWidth: 250,
				"@media (max-width: 399.95px)": {
					minWidth: "min(250px, calc(100vw - 40px))",
				},
			},
			root: {
				// It should be the same as the menu padding
				"& .MuiDivider-root": {
					marginTop: "4px !important",
					marginBottom: "4px !important",
				},
			},
		},
	},
	MuiMenuItem: {
		styleOverrides: {
			root: {
				gap: 12,

				"& .MuiSvgIcon-root": {
					fontSize: 20,
				},
			},
		},
	},
	MuiTextField: {
		styleOverrides: {
			root: {
				"& .MuiInputBase-input:-webkit-autofill": {
					boxShadow: "none", // Change the white background
					WebkitTextFillColor: "black", // Text color during autofill
					borderRadius: "none", // Prevents radius issues
				  },
			}
		},
		defaultProps: {
			InputLabelProps: {
				shrink: true,
			},
			
		},
	},
	MuiInputBase: {
		defaultProps: {
			color: "primary",
		},
		styleOverrides: {
			root: {
				height: BUTTON_LG_HEIGHT,
			},
			sizeSmall: {
				height: BUTTON_MD_HEIGHT,
				fontSize: 14,
			},
			multiline: {
				height: "auto",
			},
			["colorPrimary" as MuiStyle]: {
				// Same as button
				"& .MuiOutlinedInput-notchedOutline": {
					borderColor: tw.zinc[600],
				},
				// The default outlined input color is white, which seemed jarring.
				"&:hover:not(.Mui-error):not(.Mui-focused) .MuiOutlinedInput-notchedOutline":
					{
						borderColor: tw.zinc[500],
					},
			},
		},
	},
	MuiList: {
		defaultProps: {
			disablePadding: true,
		},
	},
	MuiIconButton: {
		styleOverrides: {
			root: {
				"&.Mui-focusVisible": {
					boxShadow: `0 0 0 2px ${tw.blue[400]}`,
				},
			},
		},
	},
} satisfies ThemeOptions["components"];
