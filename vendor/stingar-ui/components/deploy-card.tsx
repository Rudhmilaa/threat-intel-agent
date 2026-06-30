import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {Separator} from "./ui/separator";
import {DeployDialog} from "./dialogs/deploy";
import {HoneypotType} from "@/models/honeypots";

export type DeployCardProps = {
  type: HoneypotType;
  title: string;
  description: string;
};

export function DeployCard({type, title, description}: DeployCardProps) {
  return (
    <Card className="w-full min-w-0 max-w-[350px] sm:w-[350px] shadow-xl flex flex-col">
      <CardHeader className="flex-1">
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <Separator />
      </CardContent>
      <CardFooter className="flex justify-end">
        <DeployDialog type={type} title={title} />
      </CardFooter>
    </Card>
  );
}
