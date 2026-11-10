<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Secret extends Model
{
    public $timestamps = false;
    protected $keyType = 'string';
    public $incrementing = false;

    protected $fillable = [
        'id',
        'ciphertext',
        'iv',
        'wrapped_key',
        'salt',
        'max_views',
        'views',
        'expires_at',
        'created_at',
    ];

    protected $casts = [
        'max_views' => 'integer',
        'views' => 'integer',
        'expires_at' => 'datetime',
        'created_at' => 'datetime',
    ];

    /**
     * Determine if the secret has expired.
     */
    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    /**
     * Determine if the secret has reached its view limit.
     */
    public function isBurned(): bool
    {
        return $this->views >= $this->max_views;
    }
}
