import { Component, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

@Component({
  selector: 'app-root',
  template: `<main>
    <p class="eyebrow">WEBDECOY · ANGULAR SSR</p>
    <h1>See what reaches your server.</h1>
    <p>This local demo runs WebDecoy in monitor mode. Requests are observed, not blocked.</p>
    <button (click)="load()" [disabled]="busy()">{{ busy() ? 'Loading…' : 'Load public catalog' }}</button>
    <p role="status" aria-live="polite">{{ status() }}</p>
    <ul>@for (product of products(); track product.id) {<li>{{ product.name }}</li>}</ul>
    <h2>Inspect the server terminal</h2>
    <p>Run the README's curl probes to compare an ordinary request with a tripwire hit.
       The demo contains no secrets, private catalog data, or CAPTCHA.</p>
  </main>`,
  styles: [`:host{display:block;color:#202b35;font:18px/1.6 system-ui}main{max-width:700px;margin:70px auto;padding:24px}.eyebrow{font-size:12px;letter-spacing:2px;color:#466d68}h1{font-size:42px;line-height:1.15}button{background:#155f50;color:white;border:0;border-radius:8px;padding:14px 22px;font:inherit;cursor:pointer}button:disabled{opacity:.6}h2{margin-top:40px;font-size:23px}`]
})
export class App {
  private readonly http = inject(HttpClient);
  readonly busy = signal(false);
  readonly status = signal('');
  readonly products = signal<{id:number;name:string}[]>([]);
  async load() {
    if (this.busy()) return;
    this.busy.set(true);
    try {
      const data = await firstValueFrom(this.http.get<{products:{id:number;name:string}[]}>('/api/products'));
      this.products.set(data.products);
      this.status.set('Catalog loaded. Check the server terminal for the decision.');
    } catch { this.status.set('Unable to load the catalog. Please try again.'); }
    finally { this.busy.set(false); }
  }
}
