<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreSecretRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            // Max ~200KB base64 ciphertext (corresponds to <= 10,000 characters plaintext)
            'ciphertext' => ['required', 'string', 'max:200000'],
            'iv' => ['required', 'string', 'max:64'],
            'expires_in' => ['required', 'string', 'in:5m,1h,24h,7d'],
            'max_views' => ['nullable', 'integer', 'min:1', 'max:5'],
            'has_passphrase' => ['nullable', 'boolean'],
            'wrapped_key' => ['nullable', 'string', 'max:1024'],
            'salt' => ['nullable', 'string', 'max:64'],
        ];
    }
}
