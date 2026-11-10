<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class AuditLog extends Model
{
    public $timestamps = false;

    protected $fillable = [
        'event',
        'secret_id',
        'ip_hash',
        'prev_hash',
        'hash',
        'created_at',
    ];

    protected $casts = [
        'created_at' => 'datetime',
    ];
}
