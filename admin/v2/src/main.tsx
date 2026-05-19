import { render } from "preact";
import { QueryClient, QueryClientProvider } from "@tanstack/preact-query";
import { App } from "./app";
import "./style.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1
    }
  }
});

render(
  <QueryClientProvider client={queryClient}>
    <App />
  </QueryClientProvider>,
  document.getElementById("app") as HTMLElement
);
