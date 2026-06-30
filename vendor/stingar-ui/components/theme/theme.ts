import { createTheme } from "@mui/material/styles";
import { components } from "./mui";
import tw from "./tailwindColors";

declare module '@mui/material/styles' {
  interface Palette {
    customColors: {
      loginBackground: string;
      dashboardBackground: string;
      neutral: string;
    };
  }
  interface PaletteOptions {
    customColors?: {
      loginBackground?: string;
      dashboardBackground?: string;
      neutral?: string;
    };
  }
}
// Update the Button's color options to include a salmon option
declare module '@mui/material/Button' {
  interface ButtonPropsColorOverrides {
    neutral: true;
  }
}

const theme = createTheme({
  components,
  palette: {
    background: {
      default: "#ffffff",
      paper: "#ffffff",
    },
    customColors: {
      loginBackground: "#363636",
      dashboardBackground: "#ffffff",
      neutral: tw.gray[300],
    }
  },

});
export default theme;