import type { BusInterface } from "./types.js";

type MessageHandler = (msg: unknown) => Promise<void> | void;

export class LocalEventBus implements BusInterface {
  private topics: Map<string, unknown[]> = new Map();
  private subscribers: Map<string, Map<string, MessageHandler>> = new Map();

  async publish(topic: string, message: unknown): Promise<void> {
    if (!this.topics.has(topic)) {
      this.topics.set(topic, []);
    }
    this.topics.get(topic)!.push(message);

    const topicSubs = this.subscribers.get(topic);
    if (topicSubs) {
      for (const handler of topicSubs.values()) {
        await Promise.resolve(handler(message));
      }
    }
  }

  subscribe(topic: string, consumerGroup: string, handler: MessageHandler): void {
    if (!this.subscribers.has(topic)) {
      this.subscribers.set(topic, new Map());
    }
    this.subscribers.get(topic)!.set(consumerGroup, handler);
  }

  getHistory(topic: string): unknown[] {
    return this.topics.get(topic) || [];
  }

  clear(): void {
    this.topics.clear();
    this.subscribers.clear();
  }
}
